use std::{
    error::Error,
    ffi::OsString,
    process::exit
};
use clap::Parser;
use tokio::{
    fs::read,
    io::{AsyncRead, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    try_join
};
use tokio_native_tls::{
    native_tls::{Certificate, Identity, Protocol, TlsAcceptor as NativeTlsAcceptor, TlsConnector as NativeTlsConnector},
    TlsAcceptor,
    TlsConnector
};

#[derive(Parser)]
struct Cli {
    /// remote host:port
    #[arg(required_unless_present = "listen")]
    remote: Option<String>,
    /// use TLS
    #[arg(short, long)]
    tls: bool,
    /// print summary
    #[arg(short, long)]
    verbose: bool,
    /// listen and bind to local ip:port
    #[arg(short, long, value_name = "LOCAL")]
    listen: Option<String>,
    /// certificates in file
    #[arg(short, long, requires = "key")]
    cert: Option<OsString>,
    /// private key for certificate
    #[arg(short, long)]
    key: Option<OsString>,
    /// path to CA root
    #[arg(long)]
    ca: Option<OsString>,
    #[arg(long)]
    no_validate: bool,
}


/// Copy from reader to stdout and stdin to writer asynchronously
///
/// # Arguments
///
/// * `r`: AsyncRead implementation that is read and copied to stdout
/// * `w`: AsyncWrite implementation, stdin is copied and written to it
///
/// returns: Result<(u64, u64), Error> a tuple of (written, read) bytes or an io error
///
/// # Examples
///
/// ```
/// let (mut read_half, mut write_half) = split(stream); // split the stream
/// let (written, read) = copy_stdio(&mut read_half, &mut write_half).await?; // connect stdio to stream
/// ```
async fn copy_stdio<R: AsyncRead + Unpin + ?Sized, W: AsyncWrite + Unpin + ?Sized>(r: &mut R, w: &mut W) -> std::io::Result<(u64, u64)> {
    let mut stdin = tokio::io::stdin();
    let mut stdout = tokio::io::stdout();

    let (written, read) = try_join!(
        async move {
            let amount = tokio::io::copy(&mut stdin, w).await?;
            w.flush().await?;
            Ok(amount)
        }, tokio::io::copy(r, &mut stdout))?;

    Ok((written, read))
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let args = Cli::parse();

    let ca = if let Some(ca) = &args.ca {
        let ca_content = read(ca).await?;
        Some(Certificate::from_pem(&ca_content)?)
    } else { None };

    let identity = if let (Some(cert),Some(key)) = (&args.cert, &args.key) {
        let cert_content = read(cert).await?;
        let key_content = read(key).await?;
        Some(Identity::from_pkcs8(&cert_content, &key_content)?)
    } else { None };

    if args.listen.is_some() && args.tls && identity.is_none() {
        eprintln!("Cannot listen with tls without certificate");
        exit(1);
    }

    let (domain, stream, remote_address) = if let Some(listen) = &args.listen {
        let (domain, port_str) = listen.rsplit_once(':').expect("Expecting host:port as LOCAL");
        let _port: u16 = port_str.parse().expect("Cannot parse port from LOCAL");

        let listener = TcpListener::bind(listen).await?;

        let (connection, address) = listener.accept().await?;

        (domain, connection, address)
    } else {
        let remote_str = args.remote.as_deref().unwrap();

        let (domain, port_str) = remote_str.rsplit_once(':').expect("Expecting host:port as REMOTE");
        let _port: u16 = port_str.parse().expect("Cannot parse port from REMOTE");

        let connection = TcpStream::connect(remote_str).await?;

        let remote_addr = connection.peer_addr()?;

        (domain, connection, remote_addr)
    };

    if args.verbose {
        eprintln!("Connected with remote {remote_address}");
    }

    let (written, read) = if args.tls {
        let tls_stream = if args.remote.is_some() {
            let mut builder = NativeTlsConnector::builder();
            if args.no_validate {
                builder.danger_accept_invalid_certs(true)
                    .danger_accept_invalid_hostnames(true)
                    .disable_built_in_roots(true);
            } else {
                if let Some(ca) = ca { builder.disable_built_in_roots(true).add_root_certificate(ca); }
            }
            if let Some(identity) = identity { builder.identity(identity); }
            builder.min_protocol_version(Some(Protocol::Tlsv12));
            let tls_connector: TlsConnector = builder.build()?.into();
            tls_connector.connect(domain, stream).await?
        } else {
            let mut builder = NativeTlsAcceptor::builder(identity.unwrap());
            builder.min_protocol_version(Some(Protocol::Tlsv12));
            let tls_acceptor: TlsAcceptor = builder.build()?.into();
            tls_acceptor.accept(stream).await?
        };
        let (mut r, mut w) = tokio::io::split(tls_stream);
        copy_stdio(&mut r, &mut w).await?
    } else {
        let (mut r, mut w) = stream.into_split();
        copy_stdio(&mut r, &mut w).await?
    };

    if args.verbose {
        eprintln!("{written} bytes sent, {read} bytes received");
    }

    Ok(())
}
