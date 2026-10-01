//! `satspath web` — a minimal, private "Receive" web UI.
//!
//! Serves a single elegant black-and-white page with one button. Clicking it
//! computes the wallet owner's preferred receive route locally and returns the
//! QR. Everything stays private:
//!
//! - binds to `127.0.0.1` only (never exposed on the network),
//! - makes no external calls (no mempool, LNURL, DNS, or web fonts),
//! - shows only a masked alias — never the raw identifier or identity pubkey,
//! - generates the QR locally; no funds move, nothing is signed or broadcast.

use anyhow::Result;
use qrcode::{Color, QrCode};

use super::wallet::local_receive_qr;

const INDEX_HTML: &str = include_str!("web_index.html");

pub fn cmd_web(port: u16) -> Result<()> {
    let addr = format!("127.0.0.1:{port}");
    let server = tiny_http::Server::http(&addr)
        .map_err(|e| anyhow::anyhow!("could not bind {addr}: {e}"))?;

    println!("SatsPath Receive UI → http://{addr}");
    println!("Private + local only (127.0.0.1). Press Ctrl+C to stop.");

    for request in server.incoming_requests() {
        let url = request.url();
        let response = if url == "/" || url.starts_with("/?") {
            html_response(INDEX_HTML)
        } else if url.starts_with("/api/receive") {
            json_response(&receive_json())
        } else {
            tiny_http::Response::from_string("not found")
                .with_status_code(404)
                .boxed()
        };
        // A broken pipe to one client must not take the server down.
        let _ = request.respond(response);
    }
    Ok(())
}

fn receive_json() -> String {
    match local_receive_qr(None) {
        Ok(rec) => match qr_svg(&rec.payload) {
            Ok(svg) => format!(
                r#"{{"alias":{},"rail":{},"payload":{},"qr_svg":{}}}"#,
                json_str(&rec.alias),
                json_str(&rec.rail),
                json_str(&rec.payload),
                json_str(&svg),
            ),
            Err(e) => error_json(&e.to_string()),
        },
        Err(e) => error_json(&e.to_string()),
    }
}

fn error_json(msg: &str) -> String {
    format!(r#"{{"error":{}}}"#, json_str(msg))
}

/// Minimal JSON string escaping (we only emit a handful of fields).
fn json_str(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// Render a payload as a self-contained black-and-white SVG QR (no deps beyond
/// the QR matrix). Black modules on a white quiet zone.
fn qr_svg(data: &str) -> Result<String> {
    let code =
        QrCode::new(data.as_bytes()).map_err(|e| anyhow::anyhow!("could not encode QR: {e}"))?;
    let width = code.width();
    let colors = code.to_colors();
    let quiet = 4usize;
    let size = width + quiet * 2;

    let mut rects = String::new();
    for y in 0..width {
        for x in 0..width {
            if colors[y * width + x] == Color::Dark {
                rects.push_str(&format!(
                    "<rect x='{}' y='{}' width='1' height='1'/>",
                    x + quiet,
                    y + quiet
                ));
            }
        }
    }

    Ok(format!(
        "<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 {size} {size}' \
         shape-rendering='crispEdges'><rect width='100%' height='100%' fill='#fff'/>\
         <g fill='#000'>{rects}</g></svg>"
    ))
}

fn html_response(body: &str) -> tiny_http::ResponseBox {
    tiny_http::Response::from_string(body)
        .with_header(header("Content-Type", "text/html; charset=utf-8"))
        .boxed()
}

fn json_response(body: &str) -> tiny_http::ResponseBox {
    tiny_http::Response::from_string(body)
        .with_header(header("Content-Type", "application/json"))
        .boxed()
}

fn header(key: &str, value: &str) -> tiny_http::Header {
    tiny_http::Header::from_bytes(key.as_bytes(), value.as_bytes()).expect("static header is valid")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn qr_svg_is_black_and_white_svg() {
        let svg = qr_svg("bitcoin:bc1qexample?amount=0.00100000").unwrap();
        assert!(svg.starts_with("<svg"));
        assert!(svg.contains("fill='#000'"));
        assert!(svg.contains("fill='#fff'"));
        assert!(svg.contains("<rect"));
    }

    #[test]
    fn json_string_escapes_quotes_and_controls() {
        assert_eq!(json_str("a\"b"), "\"a\\\"b\"");
        assert_eq!(json_str("a\nb"), "\"a\\nb\"");
    }

    #[test]
    fn error_json_is_valid() {
        let v: serde_json::Value = serde_json::from_str(&error_json("boom")).unwrap();
        assert_eq!(v["error"], "boom");
    }
}
