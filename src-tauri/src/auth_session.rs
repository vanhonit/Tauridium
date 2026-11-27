//! macOS-only `ASWebAuthenticationSession` bridge.
//!
//! The embedded WKWebView cannot reach roaming USB/NFC security keys (CTAP2/HID)
//! through its built-in WebAuthn support. This runs a sign-in in a Safari-backed
//! `ASWebAuthenticationSession` instead, which has full WebAuthn support including
//! hardware security keys, and returns the captured callback URL to the shell.
//!
//! The session is isolated from the embedded service webviews (it shares cookies with
//! Safari, not a service's `WKWebsiteDataStore`), so this is only useful for
//! redirect/OAuth-style sign-in flows where the callback URL carries a token or code.

#![allow(deprecated)] // initWithURL_callbackURLScheme_completionHandler keeps macOS 10.15 support.
#![allow(non_snake_case)] // Apple Objective-C selector/method names in the objc2 FFI surface.

use std::cell::{Cell, RefCell};

use block2::RcBlock;
use objc2::rc::Retained;
use objc2::runtime::ProtocolObject;
use objc2::{define_class, msg_send, AllocAnyThread, MainThreadMarker, MainThreadOnly};
use objc2_app_kit::NSApplication;
use objc2_authentication_services::{
    ASWebAuthenticationPresentationContextProviding, ASWebAuthenticationSession,
    ASWebAuthenticationSessionErrorCode, ASWebAuthenticationSessionErrorDomain,
};
use objc2_foundation::{NSError, NSObject, NSObjectProtocol, NSString, NSURL};

// Objective-C ivars backing the presentation-context provider.
pub struct ProviderIvars {
    _placeholder: Cell<bool>,
}

// Provides the key window as the anchor for the system-managed auth sheet.
define_class!(
    #[unsafe(super(NSObject))]
    #[thread_kind = MainThreadOnly]
    #[name = "TauridiumAuthPresentationProvider"]
    #[ivars = ProviderIvars]
    pub struct AuthPresentationProvider;

    unsafe impl NSObjectProtocol for AuthPresentationProvider {}

    unsafe impl ASWebAuthenticationPresentationContextProviding for AuthPresentationProvider {
        #[unsafe(method_id(presentationAnchorForWebAuthenticationSession:))]
        fn presentation_anchor(&self, _session: &ASWebAuthenticationSession) -> Retained<NSObject> {
            key_window_anchor()
        }
    }
);

impl AuthPresentationProvider {
    fn new(mtm: MainThreadMarker) -> Retained<Self> {
        let this = mtm.alloc::<Self>().set_ivars(ProviderIvars {
            _placeholder: Cell::new(false),
        });
        unsafe { msg_send![super(this), init] }
    }
}

/// The key window (falling back to the first window) as the presentation anchor.
fn key_window_anchor() -> Retained<NSObject> {
    let mtm = unsafe { MainThreadMarker::new_unchecked() };
    let app = NSApplication::sharedApplication(mtm);
    let window = app
        .keyWindow()
        .or_else(|| app.windows().firstObject())
        .expect("No window available to anchor ASWebAuthenticationSession");
    // NSWindow -> NSResponder -> NSObject (two superclass hops).
    Retained::into_super(Retained::into_super(window))
}

/// Keeps an in-flight session, its presentation provider, and its completion block alive
/// until Apple invokes the completion handler and clears this slot.
struct ActiveSession {
    _session: Retained<ASWebAuthenticationSession>,
    _provider: Retained<AuthPresentationProvider>,
    _completion: RcBlock<dyn Fn(*mut NSURL, *mut NSError)>,
}

thread_local! {
    static ACTIVE_SESSION: RefCell<Option<ActiveSession>> = const { RefCell::new(None) };
}

/// Start a Safari-backed auth session and return the captured callback URL.
///
/// Returns `Ok(Some(url))` on success, `Ok(None)` when the user cancels, or an error.
pub(crate) async fn start_session(
    auth_url: String,
    callback_url_scheme: String,
    ephemeral: bool,
) -> Result<Option<String>, String> {
    if callback_url_scheme.trim().is_empty() {
        return Err("A callback URL scheme is required".to_string());
    }

    let (tx, rx) = tokio::sync::oneshot::channel::<Result<Option<String>, String>>();

    // ASWebAuthenticationSession must be created and started on the main thread.
    dispatch2::DispatchQueue::main().exec_async(move || {
        let mtm = unsafe { MainThreadMarker::new_unchecked() };

        // Drop any previous session whose cleanup has not run yet.
        ACTIVE_SESSION.with(|s| {
            *s.borrow_mut() = None;
        });

        let Some(url) = NSURL::URLWithString(&NSString::from_str(&auth_url)) else {
            let _ = tx.send(Err(format!("Invalid auth URL: {auth_url}")));
            return;
        };

        let scheme = NSString::from_str(&callback_url_scheme);

        let tx = std::sync::Arc::new(std::sync::Mutex::new(Some(tx)));
        let tx_clone = std::sync::Arc::clone(&tx);

        let completion_handler =
            RcBlock::new(move |callback_url: *mut NSURL, error: *mut NSError| {
                let result = if !error.is_null() {
                    let error = unsafe { &*error };
                    let domain = error.domain();
                    let code = error.code();
                    let expected_domain: &NSString =
                        unsafe { ASWebAuthenticationSessionErrorDomain };
                    if *domain == *expected_domain
                        && code == ASWebAuthenticationSessionErrorCode::CanceledLogin.0
                    {
                        Ok(None)
                    } else {
                        Err(format!(
                            "Auth session error: {}",
                            error.localizedDescription()
                        ))
                    }
                } else if callback_url.is_null() {
                    Err("Auth session completed without a callback URL".to_string())
                } else {
                    let url = unsafe { &*callback_url };
                    match url.absoluteString() {
                        Some(s) => Ok(Some(s.to_string())),
                        None => Err("Failed to read callback URL".to_string()),
                    }
                };

                if let Some(tx) = tx_clone.lock().ok().and_then(|mut g| g.take()) {
                    let _ = tx.send(result);
                }

                ACTIVE_SESSION.with(|s| {
                    *s.borrow_mut() = None;
                });

                // ASWebAuthenticationSession opens a separate window and closing it does not
                // restore focus to the originating app.
                let mtm = unsafe { MainThreadMarker::new_unchecked() };
                let app = NSApplication::sharedApplication(mtm);
                app.activateIgnoringOtherApps(true);
            });

        let session = unsafe {
            ASWebAuthenticationSession::initWithURL_callbackURLScheme_completionHandler(
                ASWebAuthenticationSession::alloc(),
                &url,
                Some(&scheme),
                RcBlock::as_ptr(&completion_handler),
            )
        };

        unsafe {
            session.setPrefersEphemeralWebBrowserSession(ephemeral);
        }

        // Required even on macOS so the system can anchor the auth sheet to a window.
        let provider = AuthPresentationProvider::new(mtm);
        unsafe {
            session.setPresentationContextProvider(Some(ProtocolObject::from_ref(&*provider)));
        }

        let started = unsafe { session.start() };
        if !started {
            if let Some(tx) = tx.lock().unwrap().take() {
                let _ = tx.send(Err("Failed to start ASWebAuthenticationSession".to_string()));
            }
            return;
        }

        ACTIVE_SESSION.with(|s| {
            *s.borrow_mut() = Some(ActiveSession {
                _session: session,
                _provider: provider,
                _completion: completion_handler,
            });
        });
    });

    rx.await
        .map_err(|_| "Auth session channel dropped unexpectedly".to_string())?
}
