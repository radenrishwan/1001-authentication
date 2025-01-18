package note

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/radenrishwan/notes"
	"github.com/radenrishwan/notes/authentication"
	"github.com/radenrishwan/notes/migrations/query"
)

type NotesHandler struct {
	db *pgx.Conn
}

func NewNotesHandler(db *pgx.Conn) NotesHandler {
	return NotesHandler{db: db}
}

func (h *NotesHandler) Bind(m *http.ServeMux) {
	log.Println("Binding notes handler...")

	m.HandleFunc("POST /api/notes", authentication.GoogleOauth2Middleware(func(w http.ResponseWriter, r *http.Request) {
		var request CreateNoteRequest
		err := json.NewDecoder(r.Body).Decode(&request)
		if err != nil {
			notes.WriteJsonErrorResponse(w, "failed to parse request")
			return
		}

		if err = request.Validate(); err != nil {
			notes.WriteJsonErrorResponse(w, notes.ParseErrorValidationMessage(err.Error()))
			return
		}

		// get user from context
		v, _ := r.Context().Value("user").(*authentication.GoogleUser)

		q, err := query.New(h.db).CreateNote(r.Context(), query.CreateNoteParams{
			Title:   request.Title,
			Content: request.Content,
			UserID:  v.ID,
		})

		if err != nil {
			fmt.Println(err)
			notes.WriteJsonErrorResponse(w, "failed to create notes")
			return
		}

		notes.WriteJsonResponse(w, q)
	}))

	m.HandleFunc("GET /api/notes/{id}", authentication.GoogleOauth2Middleware(func(w http.ResponseWriter, r *http.Request) {
		// get user from context
		v, _ := r.Context().Value("user").(*authentication.GoogleUser)
		id := r.PathValue("id")

		var uid pgtype.UUID
		err := uid.Scan(id)
		if err != nil {
			notes.WriteJsonErrorResponse(w, "failed to parse request")
			return
		}

		q, err := query.New(h.db).GetNote(r.Context(), uid)
		if err != nil {
			fmt.Println(err)
			notes.WriteJsonErrorResponse(w, err.Error())
			return
		}

		if q.UserID != v.ID {
			notes.WriteJsonErrorResponseWithStatus(w, "you didn't have access for this note", http.StatusUnauthorized)
			return
		}

		notes.WriteJsonResponse(w, q)
	}))

	m.HandleFunc("GET /api/notes", authentication.GoogleOauth2Middleware(func(w http.ResponseWriter, r *http.Request) {
		// get user from context
		v, _ := r.Context().Value("user").(*authentication.GoogleUser)

		// get limit, offset, and search query, if not set, use default value
		limit, err := strconv.Atoi(r.URL.Query().Get("limit"))
		if err != nil {
			notes.WriteJsonErrorResponse(w, "failed to parse request, limit is required")
			return
		}

		if limit == 0 || limit >= 50 {
			limit = 10
		}

		offset, err := strconv.Atoi(r.URL.Query().Get("offset"))
		if err != nil {
			notes.WriteJsonErrorResponse(w, "failed to parse request, offset is required")
			return
		}

		search := r.URL.Query().Get("query")
		var response []NoteResponse

		if search != "" {
			// using search query instead
			searchPattern := "%" + search + "%"
			q, err := query.New(h.db).QueryNoteByUser(r.Context(), query.QueryNoteByUserParams{
				UserID: v.ID,
				Title:  searchPattern,
				Offset: int32(offset),
				Limit:  int32(limit),
			})

			if err != nil {
				fmt.Println(err)
				notes.WriteJsonErrorResponseWithStatus(w, "failed to get notes", http.StatusInternalServerError)
				return
			}

			for _, n := range q {
				response = append(response, NoteResponse{
					Title:     n.Title,
					Content:   n.Content,
					CreatedAt: n.CreatedAt.Time.String(),
					UpdateAt:  n.CreatedAt.Time.String(),
				})
			}

			if len(response) == 0 {
				notes.WriteJsonErrorResponseWithStatus(w, "no notes found", http.StatusNotFound)
				return
			}

			notes.WriteJsonResponse(w, response)
			return
		}

		q, err := query.New(h.db).ListNotesByUser(r.Context(), query.ListNotesByUserParams{
			UserID: v.ID,
			Offset: int32(offset),
			Limit:  int32(limit),
		})

		if err != nil {
			fmt.Println(err)
			notes.WriteJsonErrorResponse(w, "failed to get notes")
			return
		}

		for _, n := range q {
			response = append(response, NoteResponse{
				Title:     n.Title,
				Content:   n.Content,
				CreatedAt: n.CreatedAt.Time.String(),
				UpdateAt:  n.CreatedAt.Time.String(),
			})
		}

		if len(response) == 0 {
			notes.WriteJsonErrorResponseWithStatus(w, "no notes found", http.StatusNotFound)
			return
		}

		notes.WriteJsonResponse(w, response)
	}))

	m.HandleFunc("PUT /api/notes/{id}", authentication.GoogleOauth2Middleware(func(w http.ResponseWriter, r *http.Request) {
		// get user from context
		v, _ := r.Context().Value("user").(*authentication.GoogleUser)
		id := r.PathValue("id")

		var uid pgtype.UUID
		err := uid.Scan(id)
		if err != nil {
			notes.WriteJsonErrorResponse(w, "failed to parse note id")
			return
		}

		existingNote, err := query.New(h.db).GetNote(r.Context(), uid)
		if err != nil {
			notes.WriteJsonErrorResponse(w, "note not found")
			return
		}

		if existingNote.UserID != v.ID {
			notes.WriteJsonErrorResponseWithStatus(w, "you don't have permission to update this note", http.StatusUnauthorized)
			return
		}

		var request UpdateNoteRequest
		err = json.NewDecoder(r.Body).Decode(&request)
		if err != nil {
			notes.WriteJsonErrorResponse(w, "failed to parse note id")
			return
		}

		if err = request.Validate(); err != nil {
			notes.WriteJsonErrorResponse(w, notes.ParseErrorValidationMessage(err.Error()))
			return
		}

		updatedNote, err := query.New(h.db).UpdateNote(r.Context(), query.UpdateNoteParams{
			ID:      uid,
			Title:   request.Title,
			Content: request.Content,
		})

		if err != nil {
			notes.WriteJsonErrorResponse(w, "failed to update note")
			return
		}

		notes.WriteJsonResponse(w, updatedNote)
	}))

	m.HandleFunc("DELETE /api/notes/{id}", authentication.GoogleOauth2Middleware(func(w http.ResponseWriter, r *http.Request) {
		// get user from context
		v, _ := r.Context().Value("user").(*authentication.GoogleUser)
		id := r.PathValue("id")

		var uid pgtype.UUID
		err := uid.Scan(id)
		if err != nil {
			notes.WriteJsonErrorResponse(w, "failed to parse note id")
			return
		}

		existingNote, err := query.New(h.db).GetNote(r.Context(), uid)
		if err != nil {
			notes.WriteJsonErrorResponse(w, "note not found")
			return
		}

		if existingNote.UserID != v.ID {
			notes.WriteJsonErrorResponseWithStatus(w, "you don't have permission to delete this note", http.StatusUnauthorized)
			return
		}

		err = query.New(h.db).DeleteNote(r.Context(), uid)
		if err != nil {
			notes.WriteJsonErrorResponse(w, "failed to delete note")
			return
		}

		notes.WriteJsonResponse(w, map[string]string{
			"message": "note deleted successfully",
		})
	}))
}
