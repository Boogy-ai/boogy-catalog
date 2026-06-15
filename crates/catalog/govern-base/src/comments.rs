//! Threaded deliberation + operator moderation.

use boogy_sdk::model::{Id, Model, Timestamp};
use boogy_sdk::pagination::CursorPage;
use boogy_sdk::store::SortDir;

use crate::models::{Comment, Proposal};
use crate::{
    db_insert, get_row, now_ms, page_params, require_voter, Deserialize, Json, Req,
    Serialize, ApiError,
};

#[derive(Deserialize, schemars::JsonSchema)]
pub struct CommentReq {
    pub body: String,
    #[serde(default)]
    pub parent_id: Option<u64>,
}

#[derive(Serialize, schemars::JsonSchema)]
pub struct CommentOut {
    pub id: u64,
    pub proposal_id: u64,
    pub parent_id: u64,
    pub author: String,
    pub body: String,
    pub created_at: i64,
}

fn comment_out(c: &Comment) -> CommentOut {
    CommentOut {
        id: c.id.get(),
        proposal_id: c.proposal_id as u64,
        parent_id: c.parent_id as u64,
        author: c.author.clone(),
        body: c.body.clone(),
        created_at: c.created_at.get(),
    }
}

/// `POST /proposals/{id}/comments` — an eligible principal adds a comment.
pub fn add_comment(req: &mut Req<'_>) -> Result<Json<CommentOut>, ApiError> {
    let author = require_voter()?;
    let id: u64 = req.params.get("id").unwrap_or("0").parse().unwrap_or(0);
    let body: CommentReq = boogy_sdk::error::parse_body(req.body())?;
    if body.body.trim().is_empty() {
        return Err(ApiError::bad_request("comment body is required"));
    }
    let _ = get_row(Proposal::TABLE, id)?.ok_or_else(ApiError::not_found)?;
    let now = Timestamp::new(now_ms());
    let comment = Comment {
        id: Id::new(0),
        owner_principal: crate::self_identity().owner,
        proposal_id: id as i64,
        parent_id: body.parent_id.unwrap_or(0) as i64,
        author,
        body: body.body,
        hidden: false,
        created_at: now,
    };
    let cid = db_insert(&comment)?;
    Ok(Json(comment_out(&Comment { id: Id::new(cid), ..comment })))
}

/// `GET /proposals/{id}/comments` — keyset-paginated, oldest-first (reading
/// order), hidden comments omitted. Read-gated.
pub fn list_comments(req: &mut Req<'_>) -> Result<Json<CursorPage<CommentOut>>, ApiError> {
    crate::gate_read()?;
    let id: u64 = req.params.get("id").unwrap_or("0").parse().unwrap_or(0);
    let (limit, cursor) = page_params(req);
    let page = crate::Query::on(Comment::TABLE)
        .where_eq(Comment::PROPOSAL_ID, id as i64)
        .where_eq(Comment::HIDDEN, false)
        .keyset_by(Comment::CREATED_AT, SortDir::Asc)
        .limit(limit)
        .cursor(cursor)
        .fetch_page(|r| comment_out(&Comment::from_row(r)))?;
    Ok(Json(page))
}
