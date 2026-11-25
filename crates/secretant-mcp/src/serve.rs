// SPDX-License-Identifier: MIT OR Apache-2.0
//! The MCP stdio shim: the one file that knows rmcp. It lists the four tools
//! and hands each call to [`Face::call`]; nothing else is reachable. The plan
//! was `mcpant`'s `backend` feature; crates.io has only its 0.0.0 placeholder,
//! so this uses rmcp 3.11 directly (pinned, stdio only, no HTTP/SSE) and the
//! swap to mcpant, or to a hand-written loop, is a change to this file alone.
//! The shape follows mcpant's `backend` module (our own, itself lifted from
//! the sageant project, MIT OR Apache-2.0).
//!
//! A tool failure is an MCP error result carrying the fixed word from
//! [`Face::call`]; no argument is echoed back.

use crate::Face;
use rmcp::model::{
    CallToolRequestParams, CallToolResponse, CallToolResult, ContentBlock, ListToolsResult,
    PaginatedRequestParams, ServerCapabilities, ServerConfig, Tool,
};
use rmcp::service::RequestContext;
use rmcp::{ErrorData as McpError, RoleServer, ServerHandler, ServiceExt};
use serde_json::{Value, json};
use std::sync::Arc;

/// Serves a [`Face`] over MCP.
#[derive(Clone)]
pub struct FaceServer {
    face: Arc<Face>,
}

impl FaceServer {
    /// Serve `face`.
    #[must_use]
    pub fn new(face: Face) -> Self {
        Self {
            face: Arc::new(face),
        }
    }

    /// Serve on this process's stdin and stdout until the client leaves.
    pub async fn run_stdio(self) -> Result<(), String> {
        let svc = self
            .serve((tokio::io::stdin(), tokio::io::stdout()))
            .await
            .map_err(|_| "could not start the MCP server".to_string())?;
        svc.waiting()
            .await
            .map(|_| ())
            .map_err(|_| "the MCP server stopped with an error".to_string())
    }
}

fn schema(v: Value) -> Arc<serde_json::Map<String, Value>> {
    match v {
        Value::Object(m) => Arc::new(m),
        _ => Arc::new(serde_json::Map::new()),
    }
}

fn placements_schema() -> Arc<serde_json::Map<String, Value>> {
    schema(
        json!({"type": "object", "required": ["placements"], "properties": {"placements": {
        "type": "array", "items": {"type": "object", "required": ["name", "path"], "properties": {
            "name": {"type": "string", "description": "A secret name; never a value"},
            "path": {"type": "string", "description": "Absolute target path inside an allow-listed directory"},
            "var": {"type": "string", "description": "For an environment file: the variable this placement owns"}}}}}}),
    )
}

fn definitions() -> Vec<Tool> {
    let none = || schema(json!({"type": "object", "properties": {}}));
    vec![
        Tool::new(
            "list_names",
            "List the secret names this role may see. Names only; no value is ever returned.",
            none(),
        ),
        Tool::new(
            "ledger_read",
            "Read what was placed where (names, targets, version numbers).",
            none(),
        ),
        Tool::new(
            "verify_placement",
            "Say whether each placement matches the store: a status word per placement, never a value.",
            placements_schema(),
        ),
        Tool::new(
            "deliver",
            "Place named secrets in named files after the person approves each path. The value goes from the store to the file and is never returned.",
            placements_schema(),
        ),
    ]
}

impl ServerHandler for FaceServer {
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(ServerCapabilities::builder().enable_tools().build()).with_instructions(
            "SecretAnt vault face. Tools return names, paths and status words only; no tool returns a secret value.",
        )
    }

    async fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, McpError> {
        Ok(ListToolsResult::with_all_items(definitions()))
    }

    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        _context: RequestContext<RoleServer>,
    ) -> Result<CallToolResponse, McpError> {
        let name = request.name.to_string();
        let args = Value::Object(request.arguments.unwrap_or_default());
        let face = Arc::clone(&self.face);
        // The approval prompt blocks on a person: keep it off the async threads.
        let out = tokio::task::spawn_blocking(move || face.call(&name, &args))
            .await
            .unwrap_or_else(|_| json!({"error": "io"}));
        let result = if out.get("error").is_some() {
            CallToolResult::error(vec![ContentBlock::text(out.to_string())])
        } else {
            CallToolResult::success(vec![ContentBlock::text(out.to_string())])
        };
        Ok(result.into())
    }
}
