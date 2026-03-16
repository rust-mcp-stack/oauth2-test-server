use axum::{extract::Query, response::Html};
use std::collections::HashMap;

pub async fn error_page(Query(params): Query<HashMap<String, String>>) -> Html<String> {
    let error = params.get("error").map(|s| s.as_str()).unwrap_or("unknown");
    Html(format!("<h1>OAuth Error: {}</h1>", error))
}
