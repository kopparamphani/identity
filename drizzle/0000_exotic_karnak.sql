CREATE TYPE "public"."auth_provider" AS ENUM('local', 'google', 'both');--> statement-breakpoint
CREATE TABLE "account" (
	"account_id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"email" text NOT NULL,
	"display_name" text NOT NULL,
	"password_hash" text,
	"auth_provider" "auth_provider" DEFAULT 'local' NOT NULL,
	"google_subject_id" text,
	"failed_login_attempts" integer DEFAULT 0 NOT NULL,
	"locked_until" timestamp with time zone,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "account_email_unique" UNIQUE("email"),
	CONSTRAINT "account_google_subject_id_unique" UNIQUE("google_subject_id")
);
--> statement-breakpoint
CREATE TABLE "session" (
	"session_id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"account_id" uuid NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"last_seen_at" timestamp with time zone DEFAULT now() NOT NULL,
	"revoked" boolean DEFAULT false NOT NULL,
	"expires_at" timestamp with time zone NOT NULL
);
--> statement-breakpoint
ALTER TABLE "session" ADD CONSTRAINT "session_account_id_account_account_id_fk" FOREIGN KEY ("account_id") REFERENCES "public"."account"("account_id") ON DELETE no action ON UPDATE no action;