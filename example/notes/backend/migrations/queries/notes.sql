-- name: CreateNote :one
INSERT INTO notes (
    title,
    content,
    user_id
) VALUES (
    $1, $2, $3
) RETURNING *;

-- name: GetNote :one
SELECT * FROM notes
WHERE id = $1 LIMIT 1;

-- name: ListNotesByUser :many
SELECT * FROM notes
WHERE user_id = $1
ORDER BY created_at DESC
OFFSET $2 LIMIT $3;

-- name: QueryNoteByUser :many
SELECT * FROM notes
WHERE user_id = $1
AND (title ILIKE $2 OR content ILIKE $2)
ORDER BY created_at DESC
OFFSET $3 LIMIT $4;

-- name: UpdateNote :one
UPDATE notes
SET title = $2,
    content = $3,
    updated_at = CURRENT_TIMESTAMP
WHERE id = $1
RETURNING *;

-- name: DeleteNote :exec
DELETE FROM notes
WHERE id = $1;
