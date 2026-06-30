ALTER TABLE "session" ADD COLUMN "token_hash" text NOT NULL;--> statement-breakpoint
ALTER TABLE "session" ADD CONSTRAINT "session_token_hash_unique" UNIQUE("token_hash");