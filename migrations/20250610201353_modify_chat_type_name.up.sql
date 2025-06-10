-- Add up migration script here
ALTER TABLE chats
RENAME COLUMN type TO chat_type;
