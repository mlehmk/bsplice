use std::{
    error::Error,
    process::exit,
    sync::Arc
};
use clap::Parser;
use tokio::{
    fs::read,
    io::{AsyncRead, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    try_join
};

#[cfg(feature = "native_tls")]
use tokio_native_tls::{native_tls::{Certificate, Identity, Protocol, TlsAcceptor as NativeTlsAcceptor, TlsConnector as NativeTlsConnector}, TlsAcceptor, TlsConnector, TlsStream};
#[cfg(feature = "rustls")]
use tokio_rustls::{TlsStream, TlsConnector, TlsAcceptor, rustls, rustls::pki_types::ServerName};

#[cfg(all(feature = "native_tls", feature = "rustls"))]
compile_error!("feature \"native_ls\" and feature \"rustls\" cannot be enabled at the same time");

#[cfg(any(feature = "rustls", feature = "native_tls"))]
mod cli {
    use std::ffi::OsString;
    use clap::Parser;

    #[derive(Parser)]
    pub struct Cli {
        /// remote host:port
        #[arg(required_unless_present = "listen")]
        pub remote: Option<String>,
        /// use TLS
        #[arg(short, long)]
        pub tls: bool,
        /// print summary
        #[arg(short, long)]
        pub verbose: bool,
        /// listen and bind to local ip:port
        #[arg(short, long, value_name = "LOCAL")]
        pub listen: Option<String>,
        /// certificates in file
        #[arg(short, long, requires = "key")]
        pub cert: Option<OsString>,
        /// private key for certificate
        #[arg(short, long)]
        pub key: Option<OsString>,
        /// path to CA root
        #[arg(long)]
        pub ca: Option<OsString>,
        /// no certificate validation for testing purposes
        #[arg(long)]
        pub no_validate: bool,
        /// do not shut down write on EOF
        #[arg(long)]
        pub no_shutdown: bool,
    }
}

#[cfg(not(any(feature = "rustls", feature = "native_tls")))]
mod cli {
    use clap::Parser;

    #[derive(Parser)]
    pub struct Cli {
        /// remote host:port
        #[arg(required_unless_present = "listen")]
        pub remote: Option<String>,
        /// print summary
        #[arg(short, long)]
        pub verbose: bool,
        /// listen and bind to local ip:port
        #[arg(short, long, value_name = "LOCAL")]
        pub listen: Option<String>,
        /// do not shut down write on EOF
        #[arg(long)]
        pub no_shutdown: bool,
    }
}

use cli::Cli;

/// Copy from reader to stdout and stdin to writer asynchronously
///
/// # Arguments
///
/// * `r`: AsyncRead implementation that is read and copied to stdout
/// * `w`: AsyncWrite implementation, stdin is copied and written to it
/// * `shutdown`: true if writing to socket should be shut down on EOF from stdin
///
/// returns: Result<(u64, u64), Error> a tuple of (written, read) bytes or an io error
///
/// # Examples
///
/// ```
/// let (mut read_half, mut write_half) = split(stream); // split the stream
/// let (written, read) = copy_stdio(&mut read_half, &mut write_half, true).await?; // connect stdio to stream
/// ```
async fn copy_stdio<R: AsyncRead + Unpin + ?Sized, W: AsyncWrite + Unpin + ?Sized>(r: &mut R, w: &mut W, shutdown: bool) -> std::io::Result<(u64, u64)> {
    let mut stdin = tokio::io::stdin();
    let mut stdout = tokio::io::stdout();

    let (written, read) = try_join!(
        async move {
            let amount = tokio::io::copy(&mut stdin, w).await?;
            w.flush().await?;
            if shutdown { w.shutdown().await? }
            Ok(amount)
        }, tokio::io::copy(r, &mut stdout))?;

    Ok((written, read))
}

#[cfg(feature = "native_tls")]
async fn connect_tls<S>(stream: S, domain: &str, no_validate: bool, ca: Option<Certificate>, identity: Option<Identity>) -> Result<TlsStream<S>, Box<dyn Error>>
    where S: AsyncRead + AsyncWrite + Unpin {
    let mut builder = NativeTlsConnector::builder();
    if no_validate {
        builder.danger_accept_invalid_certs(true)
            .danger_accept_invalid_hostnames(true)
            .disable_built_in_roots(true);
    } else {
        if let Some(ca) = ca { builder.disable_built_in_roots(true).add_root_certificate(ca); }
    }
    if let Some(identity) = identity { builder.identity(identity); }
    builder.min_protocol_version(Some(Protocol::Tlsv12));
    let tls_connector: TlsConnector = builder.build()?.into();
    Ok(tls_connector.connect(domain, stream).await?.into())
}

#[cfg(feature = "native_tls")]
async fn accept_tls<S>(stream: S, identity: Identity) -> Result<TlsStream<S>, Box<dyn Error>>
    where S: AsyncRead + AsyncWrite + Unpin {
    let mut builder = NativeTlsAcceptor::builder(identity);
    builder.min_protocol_version(Some(Protocol::Tlsv12));
    let tls_acceptor: TlsAcceptor = builder.build()?.into();
    Ok(tls_acceptor.accept(stream).await?.into())
}

#[cfg(feature = "rustls")]
mod support_types {
    use std::fmt::{Debug, Formatter};
    use std::error::Error;
    use rustls_pemfile::Item;
    use tokio_rustls::rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
    use tokio_rustls::rustls::{DigitallySignedStruct, SignatureScheme, self};
    use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};

    pub struct Certificate(CertificateDer<'static>);

    impl Certificate {
        pub fn from_pem(pem: &[u8]) -> Result<Self, Box<dyn Error>> {
            match rustls_pemfile::read_one_from_slice(pem) {
                Ok(Some((Item::X509Certificate(cert), _))) => Ok(Certificate(cert)),
                Ok(Some(_)) => Err("unexpected item found".into()),
                Ok(None) => Err("nothing found".into()),
                Err(_) => Err("some parsing error".into())
            }
        }
    }

    impl From<Certificate> for CertificateDer<'static> {
        fn from(value: Certificate) -> Self {
            value.0
        }
    }

    pub struct Identity(Vec<CertificateDer<'static>>,PrivateKeyDer<'static>);

    impl Identity {
        pub fn from_pkcs8(mut certs: &[u8], key: &[u8]) -> Result<Self, Box<dyn Error>> {
            let certs = rustls_pemfile::certs(&mut certs).collect::<Result<Vec<_>,_>>()?;

            Ok(Identity(
                certs,
                PrivatePkcs8KeyDer::from(key.to_vec()).into()
            ))
        }

        pub fn certs(&self) -> &[CertificateDer<'static>] {
            self.0.as_slice()
        }

        pub fn key(&self) -> &PrivateKeyDer<'static> {
            &self.1
        }
    }

    pub struct NoValidation;

    impl Debug for NoValidation {
        fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
            f.write_str("NoValidation")
        }
    }

    impl ServerCertVerifier for NoValidation {
        fn verify_server_cert(&self, end_entity: &CertificateDer<'_>, intermediates: &[CertificateDer<'_>], server_name: &ServerName<'_>, ocsp_response: &[u8], now: UnixTime) -> Result<ServerCertVerified, rustls::Error> {
            Ok(ServerCertVerified::assertion())
        }

        fn verify_tls12_signature(&self, message: &[u8], cert: &CertificateDer<'_>, dss: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, rustls::Error> {
            Ok(HandshakeSignatureValid::assertion())
        }

        fn verify_tls13_signature(&self, message: &[u8], cert: &CertificateDer<'_>, dss: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, rustls::Error> {
            Ok(HandshakeSignatureValid::assertion())
        }

        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            vec![
                SignatureScheme::ECDSA_NISTP256_SHA256,
                SignatureScheme::ECDSA_NISTP384_SHA384,
                SignatureScheme::ECDSA_NISTP521_SHA512,
                SignatureScheme::ED448,
                SignatureScheme::ED25519,
                SignatureScheme::RSA_PKCS1_SHA256,
                SignatureScheme::RSA_PKCS1_SHA384,
                SignatureScheme::RSA_PKCS1_SHA512,
                SignatureScheme::RSA_PSS_SHA256,
                SignatureScheme::RSA_PSS_SHA384,
                SignatureScheme::RSA_PSS_SHA512,
                SignatureScheme::RSA_PKCS1_SHA1,
                SignatureScheme::ECDSA_SHA1_Legacy
            ]
        }
    }
}

#[cfg(feature = "rustls")]
use support_types::*;

#[cfg(feature = "rustls")]
async fn connect_tls<S>(stream: S, domain: &str, no_validate: bool, ca: Option<Certificate>, identity: Option<Identity>) -> Result<TlsStream<S>, Box<dyn Error>>
    where S: AsyncRead + AsyncWrite + Unpin
{
    let server_name = ServerName::try_from(domain.to_string())?;
    let mut root_store = rustls::RootCertStore::empty();
    if let Some(cert) = ca {
        root_store.add(cert.into())?;
    } else {
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    }
    let config_builder = if no_validate {
        rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoValidation))
    } else {
        rustls::ClientConfig::builder()
            .with_root_certificates(Arc::new(root_store))
    };
    let config = if let Some(client) = identity {
        config_builder.with_client_auth_cert(client.certs().to_vec(), client.key().clone_key())?
    } else {
        config_builder.with_no_client_auth()
    };

    let connector = TlsConnector::from(Arc::new(config));
    Ok(connector.connect(server_name, stream).await?.into())
}

#[cfg(feature = "rustls")]
async fn accept_tls<S>(stream: S, identity: Identity) -> Result<TlsStream<S>, Box<dyn Error>>
    where S: AsyncRead + AsyncWrite + Unpin
{
    let config = rustls::ServerConfig::builder().with_no_client_auth().with_single_cert(identity.certs().to_vec(), identity.key().clone_key())?;
    let acceptor = TlsAcceptor::from(Arc::new(config));

    Ok(acceptor.accept(stream).await?.into())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let args = Cli::parse();

    #[cfg(any(feature = "native_tls", feature = "rustls"))]
    let ca = if let Some(ca) = &args.ca {
        let ca_content = read(ca).await?;
        Some(Certificate::from_pem(&ca_content)?)
    } else { None };

    #[cfg(any(feature = "native_tls", feature = "rustls"))]
    let identity = if let (Some(cert),Some(key)) = (&args.cert, &args.key) {
        let cert_content = read(cert).await?;
        let key_content = read(key).await?;
        Some(Identity::from_pkcs8(&cert_content, &key_content)?)
    } else { None };

    #[cfg(any(feature = "native_tls", feature = "rustls"))]
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

    #[cfg(any(feature = "native_tls", feature = "rustls"))]
    let (written, read) = if args.tls {
        let tls_stream = if args.remote.is_some() {
            connect_tls(stream, domain, args.no_validate, ca, identity).await?
        } else {
            accept_tls(stream, identity.unwrap()).await?
        };
        let (mut r, mut w) = tokio::io::split(tls_stream);
        copy_stdio(&mut r, &mut w, !args.no_shutdown).await?
    } else {
        let (mut r, mut w) = stream.into_split();
        copy_stdio(&mut r, &mut w, !args.no_shutdown).await?
    };

    #[cfg(not(any(feature = "native_tls", feature = "rustls")))]
    let (written, read) = {
        let (mut r, mut w) = stream.into_split();
        copy_stdio(&mut r, &mut w, !args.no_shutdown).await?
    };

    if args.verbose {
        eprintln!("{written} bytes sent, {read} bytes received");
    }

    Ok(())
}
