package note

import (
	validation "github.com/go-ozzo/ozzo-validation"
)

type CreateNoteRequest struct {
	Title   string `json:"title"`
	Content string `json:"content"`
}

func (self *CreateNoteRequest) Validate() error {
	return validation.ValidateStruct(self,
		validation.Field(&self.Title, validation.Required, validation.Length(1, 255)),
		validation.Field(&self.Content, validation.Required),
	)
}

type UpdateNoteRequest struct {
	Title   string `json:"title"`
	Content string `json:"content"`
}

func (self *UpdateNoteRequest) Validate() error {
	return validation.ValidateStruct(self,
		validation.Field(&self.Title, validation.Required, validation.Length(1, 255)),
		validation.Field(&self.Content, validation.Required),
	)
}

type NoteResponse struct {
	Title     string `json:"title"`
	Content   string `json:"content"`
	CreatedAt string `json:"created_at"`
	UpdateAt  string `json:"updated_at"`
}
