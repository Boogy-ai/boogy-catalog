//! MCP surface: read tools so LLM clients can inspect proposals through the
//! same auth path (tools scope by gate_read / current_principal()).

use boogy_sdk::mcp::{tool, McpServer};
use boogy_sdk::model::Model;
use boogy_sdk::store::SortDir;

use crate::models::Proposal;
use crate::proposals::{proposal_out, ProposalOut};
use crate::{Deserialize, Serialize};

use boogy_sdk::router::Req;
use boogy_sdk::response::HttpResponse;

#[derive(Deserialize, schemars::JsonSchema)]
struct ListArgs {
    #[serde(default)]
    status: Option<String>,
}

#[derive(Serialize, schemars::JsonSchema)]
struct ListResult {
    proposals: Vec<ProposalOut>,
}

fn list_proposals_tool(args: ListArgs) -> Result<ListResult, crate::ApiError> {
    crate::gate_read()?;
    let mut q = crate::Query::on(Proposal::TABLE);
    if let Some(s) = args.status.filter(|s| !s.is_empty()) {
        q = q.where_eq(Proposal::STATUS, s);
    }
    let rows = q
        .keyset_by(Proposal::CREATED_AT, SortDir::Desc)
        .limit(50)
        .fetch_all()?;
    Ok(ListResult {
        proposals: rows.iter().map(|r| proposal_out(&Proposal::from_row(r))).collect(),
    })
}

#[derive(Deserialize, schemars::JsonSchema)]
struct GetArgs {
    id: u64,
}

fn get_proposal_tool(args: GetArgs) -> Result<ProposalOut, crate::ApiError> {
    crate::gate_read()?;
    let row = crate::get_row(Proposal::TABLE, args.id)?
        .ok_or_else(crate::ApiError::not_found)?;
    Ok(proposal_out(&Proposal::from_row(&row)))
}

/// Build a fresh McpServer per request and dispatch.
pub fn mcp_dispatch(req: &mut Req<'_>) -> HttpResponse {
    McpServer::new("govern-base", env!("CARGO_PKG_VERSION"))
        .tool_typed(
            tool("list_proposals").description("List recent proposals, optionally filtered by status."),
            list_proposals_tool,
        )
        .tool_typed(
            tool("get_proposal").description("Fetch one proposal by id."),
            get_proposal_tool,
        )
        .handle(req.request)
}
