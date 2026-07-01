CREATE TABLE "password_reset" (
	"reset_id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"account_id" uuid NOT NULL,
	"token_hash" text NOT NULL,
	"expires_at" timestamp with time zone NOT NULL,
	"used_at" timestamp with time zone,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "password_reset_token_hash_unique" UNIQUE("token_hash")
);
--> statement-breakpoint
ALTER TABLE "password_reset" ADD CONSTRAINT "password_reset_account_id_account_account_id_fk" FOREIGN KEY ("account_id") REFERENCES "public"."account"("account_id") ON DELETE no action ON UPDATE no action;