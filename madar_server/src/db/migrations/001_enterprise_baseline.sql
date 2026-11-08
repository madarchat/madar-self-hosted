-- ============================================================================
-- Madar Enterprise (Self-Hosted) — sovereign baseline schema
-- ============================================================================
-- Applies `docs/NEW_DOCS/madar-Enterprise-self-hosted.md`.
--
-- One database, owned entirely by the customer. Nothing here reaches a Madar
-- server: no telemetry table, no phone-discovery index, no shared directory.
-- An organization that pulls the network cable keeps a working system.
--
-- SCOPE: workspace governance only. The personal social graph — waves,
-- moments, pulse, public invite links, phone-number discovery — is the other
-- product and is deliberately absent. `DEPLOYMENT_PROFILE=workspace` makes
-- the API refuse those routes; this schema makes the tables not exist, so the
-- data cannot be collected even by a mistake in application code.
--
-- The schema is flat (`public`) rather than split per service: a self-hosted
-- deployment is a single sovereign engine by design, not a scaled-out fleet.
-- Isolation here is organizational — one customer, one database, one server —
-- not inter-service.
-- ============================================================================

CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- ---------------------------------------------------------------------------
-- Column-sync triggers.
-- These tables carry pairs of legacy and current column names; the triggers
-- keep both populated so a rolling upgrade can read either. Defined before
-- the tables that attach them.
-- ---------------------------------------------------------------------------

CREATE FUNCTION public.sync_audit_log_cols() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
  IF (NEW.metadata IS NULL OR NEW.metadata = '{}'::jsonb) AND NEW.metadata_json IS NOT NULL THEN
    NEW.metadata := NEW.metadata_json;
  ELSIF (NEW.metadata_json IS NULL OR NEW.metadata_json = '{}'::jsonb) AND NEW.metadata IS NOT NULL THEN
    NEW.metadata_json := NEW.metadata;
  END IF;
  RETURN NEW;
END;
$$;

CREATE FUNCTION public.sync_broadcast_versions_cols() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
  IF NEW.version IS NULL AND NEW.version_no IS NOT NULL THEN
    NEW.version := NEW.version_no;
  ELSIF NEW.version_no IS NULL AND NEW.version IS NOT NULL THEN
    NEW.version_no := NEW.version;
  END IF;
  RETURN NEW;
END;
$$;

CREATE FUNCTION public.sync_channel_messages_cols() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
  IF NEW.msg_type IS NOT NULL AND (NEW.kind IS NULL OR NEW.kind = 'text') THEN
    NEW.kind := NEW.msg_type;
  ELSIF NEW.kind IS NOT NULL AND (NEW.msg_type IS NULL OR NEW.msg_type = 'text') THEN
    NEW.msg_type := NEW.kind;
  END IF;
  RETURN NEW;
END;
$$;

CREATE FUNCTION public.sync_policy_entries_columns() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
  IF NEW.key IS NULL AND NEW.policy_key IS NOT NULL THEN
    NEW.key := NEW.policy_key;
  ELSIF NEW.policy_key IS NULL AND NEW.key IS NOT NULL THEN
    NEW.policy_key := NEW.key;
  END IF;
  IF NEW.workspace_id IS NULL AND NEW.scope_type = 'workspace' THEN
    BEGIN
      NEW.workspace_id := NEW.scope_id::uuid;
    EXCEPTION WHEN OTHERS THEN
      NULL;
    END;
  END IF;
  RETURN NEW;
END;
$$;

CREATE FUNCTION public.sync_search_docs_cols() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
  IF NEW.normalized_ar IS NULL AND NEW.body_norm IS NOT NULL THEN
    NEW.normalized_ar := NEW.body_norm;
  ELSIF NEW.body_norm IS NULL AND NEW.normalized_ar IS NOT NULL THEN
    NEW.body_norm := NEW.normalized_ar;
  END IF;
  IF NEW.doc_type IS NULL AND NEW.source_type IS NOT NULL THEN
    NEW.doc_type := NEW.source_type;
  END IF;
  IF NEW.doc_id IS NULL AND NEW.source_id IS NOT NULL THEN
    NEW.doc_id := NEW.source_id;
  END IF;
  RETURN NEW;
END;
$$;


CREATE TABLE public.attachments (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    workspace_id uuid NOT NULL,
    message_id uuid,
    uploader_id integer NOT NULL,
    storage_key text,
    file_name character varying(255) NOT NULL,
    mime_type character varying(100) NOT NULL,
    byte_size bigint,
    sha256_hex character(64) NOT NULL,
    file_iv bytea NOT NULL,
    key_id character varying(32) NOT NULL,
    thumbnail_key text,
    av_scan_status character varying(16) DEFAULT 'clean'::character varying NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    size_bytes bigint,
    storage_path text,
    scan_status character varying(24) DEFAULT 'clean'::character varying NOT NULL,
    CONSTRAINT attachments_av_scan_status_check CHECK (((av_scan_status)::text = ANY (ARRAY[('pending'::character varying)::text, ('clean'::character varying)::text, ('quarantined'::character varying)::text, ('skipped'::character varying)::text])))
);
CREATE TABLE public.audit_log (
    id bigint NOT NULL,
    workspace_id uuid NOT NULL,
    actor_user_id integer,
    actor_device_id uuid,
    action character varying(64) NOT NULL,
    target_type character varying(32) NOT NULL,
    target_id text,
    metadata_json jsonb DEFAULT '{}'::jsonb NOT NULL,
    ip_hash character(32),
    prev_hash character(64) NOT NULL,
    row_hash character(64) NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    metadata jsonb DEFAULT '{}'::jsonb NOT NULL
);
CREATE SEQUENCE public.audit_log_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;
ALTER SEQUENCE public.audit_log_id_seq OWNED BY public.audit_log.id;
CREATE TABLE public.auth_codes (
    id integer NOT NULL,
    phone character varying(32) NOT NULL,
    code_hash text,
    attempts smallint DEFAULT 0 NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    consumed_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    session_info text
);
CREATE SEQUENCE public.auth_codes_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;
ALTER SEQUENCE public.auth_codes_id_seq OWNED BY public.auth_codes.id;
CREATE TABLE public.auth_providers (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    workspace_id uuid NOT NULL,
    kind character varying(16) NOT NULL,
    name character varying(80) NOT NULL,
    config_ciphertext bytea NOT NULL,
    config_iv bytea NOT NULL,
    key_id character varying(32) NOT NULL,
    enabled boolean DEFAULT true NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    sync_interval_minutes integer DEFAULT 15 NOT NULL,
    last_synced_at timestamp with time zone,
    last_sync_status character varying(32),
    last_sync_summary jsonb DEFAULT '{}'::jsonb NOT NULL,
    CONSTRAINT auth_providers_kind_check CHECK (((kind)::text = ANY (ARRAY[('local'::character varying)::text, ('oidc'::character varying)::text, ('saml'::character varying)::text, ('ldap'::character varying)::text])))
);
CREATE TABLE public.break_glass (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    workspace_id uuid NOT NULL,
    requested_by integer,
    approved_by integer,
    reason text NOT NULL,
    scope_json jsonb DEFAULT '{}'::jsonb NOT NULL,
    status character varying(32) DEFAULT 'pending'::character varying NOT NULL,
    activated_at timestamp with time zone,
    expires_at timestamp with time zone NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    initiated_by integer,
    scope text,
    CONSTRAINT break_glass_check CHECK (((approved_by IS NULL) OR (approved_by <> requested_by))),
    CONSTRAINT break_glass_status_check CHECK (((status)::text = ANY (ARRAY[('pending'::character varying)::text, ('pending_second_approval'::character varying)::text, ('active'::character varying)::text, ('expired'::character varying)::text, ('rejected'::character varying)::text])))
);
CREATE TABLE public.broadcast_receipts (
    broadcast_id uuid NOT NULL,
    user_id integer NOT NULL,
    version_no smallint DEFAULT 1 NOT NULL,
    delivered_at timestamp with time zone,
    viewed_at timestamp with time zone,
    acked_at timestamp with time zone,
    ack_device uuid,
    quiz_passed boolean,
    version_ack integer DEFAULT 1,
    ack_at timestamp with time zone,
    ack_metadata jsonb DEFAULT '{}'::jsonb NOT NULL,
    escalation_count integer DEFAULT 0 NOT NULL,
    last_escalated_at timestamp with time zone,
    device_id uuid,
    ack_type character varying(24),
    quiz_answer jsonb
);
CREATE TABLE public.broadcast_recipients (
    broadcast_id uuid NOT NULL,
    user_id integer NOT NULL,
    frozen_at timestamp with time zone DEFAULT now() NOT NULL,
    department_id uuid,
    delivered_at timestamp with time zone DEFAULT now()
);
CREATE TABLE public.broadcast_templates (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    workspace_id uuid NOT NULL,
    name character varying(120) NOT NULL,
    title_tpl character varying(200) NOT NULL,
    body_tpl text NOT NULL,
    default_ack character varying(16) DEFAULT 'scroll_ack'::character varying NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);
CREATE TABLE public.broadcast_versions (
    broadcast_id uuid NOT NULL,
    version_no smallint,
    body_ciphertext bytea NOT NULL,
    body_iv bytea NOT NULL,
    key_id character varying(32) NOT NULL,
    change_note character varying(280),
    material_change boolean DEFAULT false NOT NULL,
    created_by integer,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    id uuid DEFAULT gen_random_uuid(),
    version integer,
    title character varying(200),
    ack_reset boolean DEFAULT false NOT NULL,
    edited_by integer
);
CREATE TABLE public.broadcasts (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    workspace_id uuid NOT NULL,
    ref_no character varying(40) NOT NULL,
    sender_id integer,
    title character varying(200),
    priority character varying(16) NOT NULL,
    ack_type character varying(16) DEFAULT 'none'::character varying NOT NULL,
    ack_deadline timestamp with time zone,
    validity_until timestamp with time zone,
    quiz_json jsonb,
    current_version smallint DEFAULT 1 NOT NULL,
    published_at timestamp with time zone,
    scheduled_for timestamp with time zone,
    retracted_at timestamp with time zone,
    retract_reason character varying(280),
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    target_scope jsonb DEFAULT '{"type": "workspace"}'::jsonb NOT NULL,
    valid_until timestamp with time zone,
    retraction_reason text,
    created_by integer,
    status character varying(24) DEFAULT 'published'::character varying NOT NULL,
    target_spec jsonb DEFAULT '{"type": "workspace"}'::jsonb NOT NULL,
    CONSTRAINT broadcasts_ack_type_check CHECK (((ack_type)::text = ANY (ARRAY[('none'::character varying)::text, ('view'::character varying)::text, ('one_tap'::character varying)::text, ('scroll_to_end'::character varying)::text, ('scroll_ack'::character varying)::text, ('quiz'::character varying)::text, ('quiz_ack'::character varying)::text]))),
    CONSTRAINT broadcasts_priority_check CHECK (((priority)::text = ANY (ARRAY[('normal'::character varying)::text, ('important'::character varying)::text, ('urgent'::character varying)::text, ('urgent_ack'::character varying)::text, ('mandatory_ack'::character varying)::text, ('critical'::character varying)::text])))
);
CREATE TABLE public.calls (
    id uuid NOT NULL,
    caller_id integer,
    callee_id integer,
    kind character varying(6) NOT NULL,
    status character varying(10) DEFAULT 'ringing'::character varying NOT NULL,
    started_at timestamp with time zone DEFAULT now() NOT NULL,
    answered_at timestamp with time zone,
    ended_at timestamp with time zone,
    duration_s integer,
    end_reason character varying(40),
    CONSTRAINT calls_kind_check CHECK (((kind)::text = ANY (ARRAY[('audio'::character varying)::text, ('video'::character varying)::text]))),
    CONSTRAINT calls_status_check CHECK (((status)::text = ANY (ARRAY[('ringing'::character varying)::text, ('answered'::character varying)::text, ('ended'::character varying)::text, ('missed'::character varying)::text, ('declined'::character varying)::text, ('busy'::character varying)::text, ('failed'::character varying)::text, ('cancelled'::character varying)::text])))
);
CREATE TABLE public.channel_members (
    channel_id uuid NOT NULL,
    user_id integer NOT NULL,
    role character varying(16) DEFAULT 'member'::character varying NOT NULL,
    last_read_seq bigint DEFAULT 0 NOT NULL,
    notification_lvl character varying(16) DEFAULT 'all'::character varying NOT NULL,
    joined_at timestamp with time zone DEFAULT now() NOT NULL,
    muted boolean DEFAULT false NOT NULL,
    muted_until timestamp with time zone,
    CONSTRAINT channel_members_notification_lvl_check CHECK (((notification_lvl)::text = ANY (ARRAY[('all'::character varying)::text, ('mentions'::character varying)::text, ('mute'::character varying)::text]))),
    CONSTRAINT channel_members_role_check CHECK (((role)::text = ANY (ARRAY[('owner'::character varying)::text, ('moderator'::character varying)::text, ('member'::character varying)::text, ('guest'::character varying)::text])))
);
CREATE TABLE public.channel_messages (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    channel_id uuid NOT NULL,
    seq bigint NOT NULL,
    sender_id integer NOT NULL,
    parent_id uuid,
    client_msg_id character varying(64),
    kind character varying(16) DEFAULT 'text'::character varying NOT NULL,
    body_ciphertext bytea,
    body_iv bytea,
    key_id character varying(32),
    metadata_json jsonb DEFAULT '{}'::jsonb NOT NULL,
    pinned_at timestamp with time zone,
    pinned_by integer,
    edited_at timestamp with time zone,
    deleted_at timestamp with time zone,
    legal_hold boolean DEFAULT false NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    reply_to_id uuid,
    media_url text,
    media_mime character varying(120),
    media_size integer,
    media_duration_ms integer,
    metadata jsonb DEFAULT '{}'::jsonb NOT NULL,
    is_deleted boolean DEFAULT false NOT NULL,
    msg_type character varying(24) DEFAULT 'text'::character varying NOT NULL,
    e2ee_envelope jsonb,
    CONSTRAINT channel_messages_kind_check CHECK (((kind)::text = ANY (ARRAY[('text'::character varying)::text, ('file'::character varying)::text, ('image'::character varying)::text, ('audio'::character varying)::text, ('voice'::character varying)::text, ('video'::character varying)::text, ('system'::character varying)::text, ('decision_card'::character varying)::text, ('followup_card'::character varying)::text])))
);
CREATE TABLE public.channel_references (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    channel_id uuid NOT NULL,
    title character varying(160) NOT NULL,
    kind character varying(16) DEFAULT 'link'::character varying NOT NULL,
    target_ref text,
    pinned_order smallint DEFAULT 0 NOT NULL,
    added_by integer,
    added_at timestamp with time zone DEFAULT now() NOT NULL,
    workspace_id uuid,
    ref_type character varying(32) DEFAULT 'link'::character varying NOT NULL,
    url text,
    description text,
    created_by integer,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    target_url text,
    attachment_id uuid,
    message_id uuid,
    pinned_by integer,
    pinned_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT channel_references_kind_check CHECK (((kind)::text = ANY (ARRAY[('file'::character varying)::text, ('link'::character varying)::text, ('broadcast'::character varying)::text, ('decision'::character varying)::text])))
);
CREATE TABLE public.channels (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    workspace_id uuid NOT NULL,
    kind character varying(16) NOT NULL,
    name character varying(120),
    purpose character varying(280),
    department_id uuid,
    is_archived boolean DEFAULT false NOT NULL,
    posting_mode character varying(16) DEFAULT 'all'::character varying NOT NULL,
    retention_days integer,
    last_seq bigint DEFAULT 0 NOT NULL,
    created_by integer,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    last_message_at timestamp with time zone,
    description text,
    legal_hold boolean DEFAULT false NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    privacy_mode character varying(24) DEFAULT 'standard_governed'::character varying NOT NULL,
    e2ee_epoch integer DEFAULT 1 NOT NULL,
    CONSTRAINT channels_kind_check CHECK (((kind)::text = ANY (ARRAY[('direct'::character varying)::text, ('private_group'::character varying)::text, ('public_channel'::character varying)::text, ('department'::character varying)::text, ('broadcast_feed'::character varying)::text, ('dm'::character varying)::text, ('group'::character varying)::text, ('project'::character varying)::text, ('announcement'::character varying)::text, ('external'::character varying)::text]))),
    CONSTRAINT channels_posting_mode_check CHECK (((posting_mode)::text = ANY (ARRAY[('all'::character varying)::text, ('moderators_only'::character varying)::text, ('read_only'::character varying)::text]))),
    CONSTRAINT channels_privacy_mode_check CHECK (((privacy_mode)::text = ANY (ARRAY[('standard_governed'::character varying)::text, ('confidential_e2ee'::character varying)::text, ('enhanced_privacy'::character varying)::text])))
);
CREATE TABLE public.credentials (
    user_id integer NOT NULL,
    password_hash text NOT NULL,
    must_change_password boolean DEFAULT false NOT NULL,
    password_changed_at timestamp with time zone DEFAULT now() NOT NULL
);
CREATE TABLE public.decisions (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    workspace_id uuid NOT NULL,
    channel_id uuid NOT NULL,
    source_message_id uuid,
    title character varying(240) NOT NULL,
    rationale text,
    owner_user_id integer,
    status character varying(16) DEFAULT 'active'::character varying NOT NULL,
    superseded_by uuid,
    created_by integer,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    message_id uuid,
    summary text,
    owner_id integer,
    decided_at timestamp with time zone DEFAULT now() NOT NULL,
    source_msg_id uuid,
    decided_by integer,
    CONSTRAINT decisions_status_check CHECK (((status)::text = ANY (ARRAY[('active'::character varying)::text, ('superseded'::character varying)::text])))
);
CREATE TABLE public.departments (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    workspace_id uuid NOT NULL,
    parent_id uuid,
    name character varying(120) NOT NULL,
    code character varying(32),
    manager_user_id integer,
    auto_channel_id uuid,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    head_user_id integer,
    channel_id uuid,
    sort_order integer DEFAULT 0 NOT NULL
);
CREATE TABLE public.devices (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    user_id integer NOT NULL,
    workspace_id uuid,
    device_name character varying(120) NOT NULL,
    platform character varying(16) NOT NULL,
    os_version character varying(40),
    app_version character varying(32),
    device_pub_key text NOT NULL,
    push_handle character varying(128),
    attestation_state character varying(16) DEFAULT 'unverified'::character varying NOT NULL,
    status character varying(16) DEFAULT 'active'::character varying NOT NULL,
    policy_version integer DEFAULT 0 NOT NULL,
    policy_applied_at timestamp with time zone,
    last_seen_at timestamp with time zone,
    last_ip_hash character(32),
    wipe_requested_at timestamp with time zone,
    wipe_acked_at timestamp with time zone,
    wipe_ack_sig text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    fingerprint character varying(255),
    wipe_command_id uuid,
    wiped_at timestamp with time zone,
    CONSTRAINT devices_attestation_state_check CHECK (((attestation_state)::text = ANY (ARRAY[('verified'::character varying)::text, ('unverified'::character varying)::text, ('compromised'::character varying)::text]))),
    CONSTRAINT devices_platform_check CHECK (((platform)::text = ANY (ARRAY[('android'::character varying)::text, ('ios'::character varying)::text, ('web'::character varying)::text, ('desktop'::character varying)::text]))),
    CONSTRAINT devices_status_check CHECK (((status)::text = ANY (ARRAY[('active'::character varying)::text, ('suspended'::character varying)::text, ('revoked'::character varying)::text, ('wipe_pending'::character varying)::text, ('wiped'::character varying)::text])))
);
CREATE TABLE public.enrollment_tokens (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    workspace_id uuid NOT NULL,
    target_user_id integer,
    default_group_id uuid,
    token_hash character(64) NOT NULL,
    jws_compact text,
    max_uses smallint DEFAULT 1 NOT NULL,
    used_count smallint DEFAULT 0 NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    revoked_at timestamp with time zone,
    created_by integer,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);
CREATE TABLE public.followups (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    workspace_id uuid NOT NULL,
    channel_id uuid NOT NULL,
    source_message_id uuid,
    title character varying(240) NOT NULL,
    assignee_user_id integer,
    due_at timestamp with time zone,
    status character varying(12) DEFAULT 'open'::character varying NOT NULL,
    completed_at timestamp with time zone,
    completion_note character varying(280),
    created_by integer,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    message_id uuid,
    notes text,
    owner_id integer,
    due_date timestamp with time zone,
    source_msg_id uuid,
    CONSTRAINT followups_status_check CHECK (((status)::text = ANY (ARRAY[('open'::character varying)::text, ('done'::character varying)::text])))
);
CREATE TABLE public.hub_items (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    workspace_id uuid NOT NULL,
    user_id integer NOT NULL,
    section character varying(16) DEFAULT 'requires_action'::character varying NOT NULL,
    item_kind character varying(24) DEFAULT 'broadcast_ack'::character varying,
    ref_id uuid,
    title character varying(240),
    due_at timestamp with time zone,
    resolved_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    source_type character varying(32),
    source_id uuid,
    metadata jsonb DEFAULT '{}'::jsonb NOT NULL,
    priority integer DEFAULT 50 NOT NULL,
    CONSTRAINT hub_items_section_check CHECK (((section)::text = ANY (ARRAY[('requires_action'::character varying)::text, ('followups'::character varying)::text, ('announcements'::character varying)::text])))
);
CREATE TABLE public.legal_holds (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    workspace_id uuid NOT NULL,
    title character varying(160) DEFAULT 'أمر تحفظ قانوني'::character varying NOT NULL,
    reason text NOT NULL,
    scope_json jsonb DEFAULT '{}'::jsonb NOT NULL,
    created_by integer,
    released_by integer,
    released_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    scope_type character varying(24),
    scope_id text,
    matter_ref character varying(160),
    placed_by integer
);
CREATE TABLE public.mentions (
    id bigint NOT NULL,
    message_id uuid NOT NULL,
    mentioned_id integer,
    mention_kind character varying(16) DEFAULT 'user'::character varying NOT NULL,
    read_at timestamp with time zone,
    mentioned_user_id integer,
    CONSTRAINT mentions_mention_kind_check CHECK (((mention_kind)::text = ANY (ARRAY[('user'::character varying)::text, ('channel'::character varying)::text, ('here'::character varying)::text])))
);
CREATE SEQUENCE public.mentions_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;
ALTER SEQUENCE public.mentions_id_seq OWNED BY public.mentions.id;
CREATE TABLE public.message_edits (
    id bigint NOT NULL,
    message_id uuid NOT NULL,
    prev_ciphertext bytea,
    prev_iv bytea,
    key_id character varying(32),
    edited_by integer,
    edited_at timestamp with time zone DEFAULT now() NOT NULL,
    previous_ciphertext bytea,
    previous_iv bytea,
    previous_key_id character varying(32)
);
CREATE SEQUENCE public.message_edits_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;
ALTER SEQUENCE public.message_edits_id_seq OWNED BY public.message_edits.id;
CREATE TABLE public.messages (
    id bigint NOT NULL,
    thread_id integer NOT NULL,
    sender_id integer NOT NULL,
    client_id character varying(64),
    kind character varying(10) DEFAULT 'text'::character varying NOT NULL,
    body text,
    media_url text,
    thumb_url text,
    media_mime character varying(100),
    media_name character varying(255),
    media_size bigint,
    duration_ms integer,
    reply_to_id bigint,
    moment_id integer,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    edited_at timestamp with time zone,
    deleted_at timestamp with time zone,
    is_e2ee boolean DEFAULT false NOT NULL,
    e2ee_header jsonb,
    CONSTRAINT messages_kind_check CHECK (((kind)::text = ANY (ARRAY[('text'::character varying)::text, ('image'::character varying)::text, ('video'::character varying)::text, ('audio'::character varying)::text, ('file'::character varying)::text, ('system'::character varying)::text])))
);
CREATE SEQUENCE public.messages_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;
ALTER SEQUENCE public.messages_id_seq OWNED BY public.messages.id;
CREATE TABLE public.mfa_factors (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    user_id integer NOT NULL,
    kind character varying(16) NOT NULL,
    secret_ciphertext bytea NOT NULL,
    secret_iv bytea NOT NULL,
    key_id character varying(32) NOT NULL,
    verified_at timestamp with time zone,
    last_used_step bigint,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT mfa_factors_kind_check CHECK (((kind)::text = 'totp'::text))
);
CREATE TABLE public.offline_message_queue (
    id bigint NOT NULL,
    recipient_id integer NOT NULL,
    thread_id integer NOT NULL,
    message_id bigint NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);
CREATE SEQUENCE public.offline_message_queue_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;
ALTER SEQUENCE public.offline_message_queue_id_seq OWNED BY public.offline_message_queue.id;
CREATE TABLE public.policy_entries (
    id bigint NOT NULL,
    scope_type character varying(16) NOT NULL,
    scope_id text NOT NULL,
    policy_key character varying(80),
    value_json jsonb NOT NULL,
    locked boolean DEFAULT false NOT NULL,
    updated_by integer,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    workspace_id uuid,
    key character varying(80),
    CONSTRAINT policy_entries_scope_type_check CHECK (((scope_type)::text = ANY (ARRAY[('workspace'::character varying)::text, ('department'::character varying)::text, ('group'::character varying)::text, ('user'::character varying)::text])))
);
CREATE SEQUENCE public.policy_entries_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;
ALTER SEQUENCE public.policy_entries_id_seq OWNED BY public.policy_entries.id;
CREATE TABLE public.policy_group_members (
    group_id uuid NOT NULL,
    user_id integer,
    department_id uuid,
    CONSTRAINT policy_group_members_check CHECK (((user_id IS NOT NULL) <> (department_id IS NOT NULL)))
);
CREATE TABLE public.policy_groups (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    workspace_id uuid NOT NULL,
    name character varying(120) NOT NULL,
    description character varying(280),
    priority integer DEFAULT 100 NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);
CREATE TABLE public.policy_signing_keys (
    kid character varying(32) NOT NULL,
    workspace_id uuid NOT NULL,
    public_key_ed25519 text NOT NULL,
    private_ciphertext bytea NOT NULL,
    private_iv bytea NOT NULL,
    key_id character varying(32) NOT NULL,
    active boolean DEFAULT true NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    retired_at timestamp with time zone
);
CREATE TABLE public.policy_versions (
    version integer NOT NULL,
    workspace_id uuid NOT NULL,
    summary character varying(280),
    published_by integer,
    published_at timestamp with time zone DEFAULT now() NOT NULL,
    reason text,
    diff_json jsonb DEFAULT '{}'::jsonb NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);
CREATE SEQUENCE public.policy_versions_version_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;
ALTER SEQUENCE public.policy_versions_version_seq OWNED BY public.policy_versions.version;
CREATE TABLE public.reactions (
    message_id uuid NOT NULL,
    user_id integer NOT NULL,
    emoji character varying(16) NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);
CREATE TABLE public.recovery_codes (
    id bigint NOT NULL,
    user_id integer NOT NULL,
    code_hash character(64) NOT NULL,
    used_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);
CREATE SEQUENCE public.recovery_codes_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;
ALTER SEQUENCE public.recovery_codes_id_seq OWNED BY public.recovery_codes.id;
CREATE TABLE public.refresh_tokens (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    device_id uuid NOT NULL,
    user_id integer NOT NULL,
    token_hash character(64) NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    revoked_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);
CREATE TABLE public.relay_push_handles (
    push_handle character varying(128) NOT NULL,
    workspace_id uuid,
    device_id uuid,
    platform character varying(16) NOT NULL,
    native_token_ciphertext bytea NOT NULL,
    native_token_iv bytea NOT NULL,
    key_id character varying(32) NOT NULL,
    wake_count integer DEFAULT 0 NOT NULL,
    last_wake_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT relay_push_handles_platform_check CHECK (((platform)::text = ANY (ARRAY[('android'::character varying)::text, ('ios'::character varying)::text, ('web'::character varying)::text, ('desktop'::character varying)::text, ('flutter'::character varying)::text])))
);
CREATE TABLE public.relay_wake_events (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    push_handle character varying(128) NOT NULL,
    vault_id character varying(128) NOT NULL,
    sync_hint character varying(32) DEFAULT 'normal'::character varying NOT NULL,
    priority character varying(16) DEFAULT 'high'::character varying NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);
CREATE TABLE public.search_docs (
    doc_type character varying(16),
    doc_id uuid,
    workspace_id uuid NOT NULL,
    channel_id uuid,
    normalized_ar text,
    tsv tsvector GENERATED ALWAYS AS (to_tsvector('simple'::regconfig, normalized_ar)) STORED,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    id uuid DEFAULT gen_random_uuid(),
    source_type character varying(32),
    source_id uuid,
    title text,
    body_norm text,
    metadata jsonb DEFAULT '{}'::jsonb NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT search_docs_doc_type_check CHECK (((doc_type)::text = ANY (ARRAY[('message'::character varying)::text, ('broadcast'::character varying)::text, ('decision'::character varying)::text, ('followup'::character varying)::text, ('reference'::character varying)::text])))
);
CREATE TABLE public.service_entitlements (
    workspace_id uuid NOT NULL,
    service_code character varying(32) NOT NULL,
    enabled boolean DEFAULT false NOT NULL,
    quota_limit integer,
    quota_used integer DEFAULT 0 NOT NULL,
    expires_at timestamp with time zone,
    CONSTRAINT service_entitlements_service_code_check CHECK (((service_code)::text = ANY (ARRAY[('push_relay'::character varying)::text, ('sms_otp'::character varying)::text, ('cloud_backup'::character varying)::text, ('managed_turn'::character varying)::text])))
);
CREATE TABLE public.sessions (
    id uuid NOT NULL,
    user_id integer NOT NULL,
    refresh_token_hash text NOT NULL,
    device_name character varying(120),
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    last_used_at timestamp with time zone,
    expires_at timestamp with time zone NOT NULL,
    revoked_at timestamp with time zone
);
CREATE TABLE public.thread_members (
    thread_id integer NOT NULL,
    user_id integer NOT NULL,
    role character varying(8) DEFAULT 'member'::character varying NOT NULL,
    joined_at timestamp with time zone DEFAULT now() NOT NULL,
    last_read_message_id bigint DEFAULT 0,
    muted boolean DEFAULT false NOT NULL
);
CREATE TABLE public.threads (
    id integer NOT NULL,
    kind character varying(8) DEFAULT 'direct'::character varying NOT NULL,
    title character varying(120),
    avatar_url text,
    created_by integer,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    last_message_at timestamp with time zone,
    CONSTRAINT threads_kind_check CHECK (((kind)::text = ANY (ARRAY[('direct'::character varying)::text, ('group'::character varying)::text])))
);
CREATE SEQUENCE public.threads_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;
ALTER SEQUENCE public.threads_id_seq OWNED BY public.threads.id;
CREATE TABLE public.user_blocks (
    blocker_id integer NOT NULL,
    blocked_id integer NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT user_blocks_check CHECK ((blocker_id <> blocked_id))
);
CREATE TABLE public.user_key_bundles (
    user_id integer NOT NULL,
    identity_key text NOT NULL,
    signed_prekey_id integer DEFAULT 1 NOT NULL,
    signed_prekey text NOT NULL,
    signed_prekey_sig text NOT NULL,
    one_time_prekeys jsonb DEFAULT '[]'::jsonb NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    signing_key text,
    identity_generation integer DEFAULT 1 NOT NULL,
    previous_identity_key text
);
CREATE TABLE public.user_roles (
    id bigint NOT NULL,
    user_id integer NOT NULL,
    role character varying(32) NOT NULL,
    scope_department_id uuid,
    granted_by integer,
    granted_at timestamp with time zone DEFAULT now() NOT NULL,
    scope_dept_id uuid,
    CONSTRAINT user_roles_role_check CHECK (((role)::text = ANY (ARRAY[('SUPER_ADMIN'::character varying)::text, ('EXEC_MANAGER'::character varying)::text, ('IT_ADMIN'::character varying)::text, ('COMPLIANCE_OFFICER'::character varying)::text, ('DEPT_HEAD'::character varying)::text, ('BROADCASTER'::character varying)::text, ('MODERATOR'::character varying)::text, ('MEMBER'::character varying)::text, ('GUEST'::character varying)::text])))
);
CREATE SEQUENCE public.user_roles_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;
ALTER SEQUENCE public.user_roles_id_seq OWNED BY public.user_roles.id;
CREATE TABLE public.users (
    id integer NOT NULL,
    phone character varying(32),
    name character varying(80),
    note character varying(140) DEFAULT ''::character varying,
    avatar_url text,
    accent character varying(16) DEFAULT 'teal'::character varying,
    push_token text,
    device_platform character varying(20),
    last_seen_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    allow_phone_discovery boolean DEFAULT false NOT NULL,
    show_phone_number boolean DEFAULT false NOT NULL,
    phone_e164 character varying(20),
    workspace_id uuid,
    employee_no character varying(64),
    email character varying(255),
    work_phone character varying(32),
    title character varying(120),
    department_id uuid,
    account_status character varying(20) DEFAULT 'active'::character varying NOT NULL,
    profile_type character varying(16) DEFAULT 'personal'::character varying NOT NULL,
    presence_status character varying(24) DEFAULT 'available'::character varying NOT NULL,
    presence_note character varying(140),
    presence_until timestamp with time zone,
    failed_login_attempts smallint DEFAULT 0 NOT NULL,
    locked_until timestamp with time zone,
    custom_status jsonb DEFAULT '{}'::jsonb NOT NULL,
    offboarded_at timestamp with time zone,
    external_idp_id character varying(255),
    auth_provider_id uuid,
    CONSTRAINT users_account_status_check CHECK (((account_status)::text = ANY (ARRAY[('invited'::character varying)::text, ('active'::character varying)::text, ('suspended'::character varying)::text, ('offboarded'::character varying)::text]))),
    CONSTRAINT users_presence_status_check CHECK (((presence_status)::text = ANY (ARRAY[('available'::character varying)::text, ('online'::character varying)::text, ('in_meeting'::character varying)::text, ('do_not_disturb'::character varying)::text, ('focus'::character varying)::text, ('away'::character varying)::text, ('on_leave'::character varying)::text, ('offline'::character varying)::text]))),
    CONSTRAINT users_profile_type_check CHECK (((profile_type)::text = ANY (ARRAY[('workspace'::character varying)::text, ('personal'::character varying)::text])))
);
CREATE SEQUENCE public.users_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;
ALTER SEQUENCE public.users_id_seq OWNED BY public.users.id;
CREATE TABLE public.workspace (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    name character varying(160) NOT NULL,
    logo_url text,
    primary_color character varying(16) DEFAULT '#0F766E'::character varying NOT NULL,
    locale character varying(8) DEFAULT 'ar'::character varying NOT NULL,
    timezone character varying(64) DEFAULT 'Asia/Riyadh'::character varying NOT NULL,
    deployment_profile character varying(24) DEFAULT 'workspace'::character varying NOT NULL,
    setup_completed boolean DEFAULT false NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    policy_signing_pub text,
    policy_signing_pub_key text,
    official_domain character varying(255),
    domain_verify_token character varying(128),
    domain_verified boolean DEFAULT false NOT NULL,
    domain_verified_at timestamp with time zone,
    cloud_services_config jsonb DEFAULT '{}'::jsonb NOT NULL
);
ALTER TABLE ONLY public.audit_log ALTER COLUMN id SET DEFAULT nextval('public.audit_log_id_seq'::regclass);
ALTER TABLE ONLY public.auth_codes ALTER COLUMN id SET DEFAULT nextval('public.auth_codes_id_seq'::regclass);
ALTER TABLE ONLY public.mentions ALTER COLUMN id SET DEFAULT nextval('public.mentions_id_seq'::regclass);
ALTER TABLE ONLY public.message_edits ALTER COLUMN id SET DEFAULT nextval('public.message_edits_id_seq'::regclass);
ALTER TABLE ONLY public.messages ALTER COLUMN id SET DEFAULT nextval('public.messages_id_seq'::regclass);
ALTER TABLE ONLY public.offline_message_queue ALTER COLUMN id SET DEFAULT nextval('public.offline_message_queue_id_seq'::regclass);
ALTER TABLE ONLY public.policy_entries ALTER COLUMN id SET DEFAULT nextval('public.policy_entries_id_seq'::regclass);
ALTER TABLE ONLY public.policy_versions ALTER COLUMN version SET DEFAULT nextval('public.policy_versions_version_seq'::regclass);
ALTER TABLE ONLY public.recovery_codes ALTER COLUMN id SET DEFAULT nextval('public.recovery_codes_id_seq'::regclass);
ALTER TABLE ONLY public.threads ALTER COLUMN id SET DEFAULT nextval('public.threads_id_seq'::regclass);
ALTER TABLE ONLY public.user_roles ALTER COLUMN id SET DEFAULT nextval('public.user_roles_id_seq'::regclass);
ALTER TABLE ONLY public.users ALTER COLUMN id SET DEFAULT nextval('public.users_id_seq'::regclass);
ALTER TABLE ONLY public.attachments
    ADD CONSTRAINT attachments_pkey PRIMARY KEY (id);
ALTER TABLE ONLY public.audit_log
    ADD CONSTRAINT audit_log_pkey PRIMARY KEY (id);
ALTER TABLE ONLY public.auth_codes
    ADD CONSTRAINT auth_codes_pkey PRIMARY KEY (id);
ALTER TABLE ONLY public.auth_providers
    ADD CONSTRAINT auth_providers_pkey PRIMARY KEY (id);
ALTER TABLE ONLY public.break_glass
    ADD CONSTRAINT break_glass_pkey PRIMARY KEY (id);
ALTER TABLE ONLY public.broadcast_recipients
    ADD CONSTRAINT broadcast_recipients_pkey PRIMARY KEY (broadcast_id, user_id);
ALTER TABLE ONLY public.broadcast_templates
    ADD CONSTRAINT broadcast_templates_pkey PRIMARY KEY (id);
ALTER TABLE ONLY public.broadcasts
    ADD CONSTRAINT broadcasts_pkey PRIMARY KEY (id);
ALTER TABLE ONLY public.broadcasts
    ADD CONSTRAINT broadcasts_ref_no_key UNIQUE (ref_no);
ALTER TABLE ONLY public.calls
    ADD CONSTRAINT calls_pkey PRIMARY KEY (id);
ALTER TABLE ONLY public.channel_members
    ADD CONSTRAINT channel_members_pkey PRIMARY KEY (channel_id, user_id);
ALTER TABLE ONLY public.channel_messages
    ADD CONSTRAINT channel_messages_channel_id_seq_key UNIQUE (channel_id, seq);
ALTER TABLE ONLY public.channel_messages
    ADD CONSTRAINT channel_messages_pkey PRIMARY KEY (id);
ALTER TABLE ONLY public.channel_messages
    ADD CONSTRAINT channel_messages_sender_id_client_msg_id_key UNIQUE (sender_id, client_msg_id);
ALTER TABLE ONLY public.channel_references
    ADD CONSTRAINT channel_references_pkey PRIMARY KEY (id);
ALTER TABLE ONLY public.channels
    ADD CONSTRAINT channels_pkey PRIMARY KEY (id);
ALTER TABLE ONLY public.credentials
    ADD CONSTRAINT credentials_pkey PRIMARY KEY (user_id);
ALTER TABLE ONLY public.decisions
    ADD CONSTRAINT decisions_pkey PRIMARY KEY (id);
ALTER TABLE ONLY public.departments
    ADD CONSTRAINT departments_pkey PRIMARY KEY (id);
ALTER TABLE ONLY public.devices
    ADD CONSTRAINT devices_pkey PRIMARY KEY (id);
ALTER TABLE ONLY public.enrollment_tokens
    ADD CONSTRAINT enrollment_tokens_pkey PRIMARY KEY (id);
ALTER TABLE ONLY public.enrollment_tokens
    ADD CONSTRAINT enrollment_tokens_token_hash_key UNIQUE (token_hash);
ALTER TABLE ONLY public.followups
    ADD CONSTRAINT followups_pkey PRIMARY KEY (id);
ALTER TABLE ONLY public.hub_items
    ADD CONSTRAINT hub_items_pkey PRIMARY KEY (id);
ALTER TABLE ONLY public.legal_holds
    ADD CONSTRAINT legal_holds_pkey PRIMARY KEY (id);
ALTER TABLE ONLY public.mentions
    ADD CONSTRAINT mentions_pkey PRIMARY KEY (id);
ALTER TABLE ONLY public.message_edits
    ADD CONSTRAINT message_edits_pkey PRIMARY KEY (id);
ALTER TABLE ONLY public.messages
    ADD CONSTRAINT messages_pkey PRIMARY KEY (id);
ALTER TABLE ONLY public.mfa_factors
    ADD CONSTRAINT mfa_factors_pkey PRIMARY KEY (id);
ALTER TABLE ONLY public.offline_message_queue
    ADD CONSTRAINT offline_message_queue_pkey PRIMARY KEY (id);
ALTER TABLE ONLY public.offline_message_queue
    ADD CONSTRAINT offline_message_queue_recipient_id_message_id_key UNIQUE (recipient_id, message_id);
ALTER TABLE ONLY public.policy_entries
    ADD CONSTRAINT policy_entries_pkey PRIMARY KEY (id);
ALTER TABLE ONLY public.policy_groups
    ADD CONSTRAINT policy_groups_pkey PRIMARY KEY (id);
ALTER TABLE ONLY public.policy_signing_keys
    ADD CONSTRAINT policy_signing_keys_pkey PRIMARY KEY (kid);
ALTER TABLE ONLY public.policy_versions
    ADD CONSTRAINT policy_versions_pkey PRIMARY KEY (version);
ALTER TABLE ONLY public.recovery_codes
    ADD CONSTRAINT recovery_codes_pkey PRIMARY KEY (id);
ALTER TABLE ONLY public.refresh_tokens
    ADD CONSTRAINT refresh_tokens_pkey PRIMARY KEY (id);
ALTER TABLE ONLY public.refresh_tokens
    ADD CONSTRAINT refresh_tokens_token_hash_key UNIQUE (token_hash);
ALTER TABLE ONLY public.relay_push_handles
    ADD CONSTRAINT relay_push_handles_pkey PRIMARY KEY (push_handle);
ALTER TABLE ONLY public.relay_wake_events
    ADD CONSTRAINT relay_wake_events_pkey PRIMARY KEY (id);
ALTER TABLE ONLY public.service_entitlements
    ADD CONSTRAINT service_entitlements_pkey PRIMARY KEY (workspace_id, service_code);
ALTER TABLE ONLY public.sessions
    ADD CONSTRAINT sessions_pkey PRIMARY KEY (id);
ALTER TABLE ONLY public.thread_members
    ADD CONSTRAINT thread_members_pkey PRIMARY KEY (thread_id, user_id);
ALTER TABLE ONLY public.threads
    ADD CONSTRAINT threads_pkey PRIMARY KEY (id);
ALTER TABLE ONLY public.user_blocks
    ADD CONSTRAINT user_blocks_pkey PRIMARY KEY (blocker_id, blocked_id);
ALTER TABLE ONLY public.user_key_bundles
    ADD CONSTRAINT user_key_bundles_pkey PRIMARY KEY (user_id);
ALTER TABLE ONLY public.user_roles
    ADD CONSTRAINT user_roles_pkey PRIMARY KEY (id);
ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_phone_key UNIQUE (phone);
ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_pkey PRIMARY KEY (id);
ALTER TABLE ONLY public.workspace
    ADD CONSTRAINT workspace_pkey PRIMARY KEY (id);
CREATE INDEX idx_audit_action ON public.audit_log USING btree (workspace_id, action, created_at DESC);
CREATE INDEX idx_audit_time ON public.audit_log USING btree (workspace_id, created_at DESC);
CREATE INDEX idx_auth_codes_phone ON public.auth_codes USING btree (phone, created_at DESC);
CREATE UNIQUE INDEX idx_broadcast_receipts_bcast_user ON public.broadcast_receipts USING btree (broadcast_id, user_id);
CREATE UNIQUE INDEX idx_broadcast_receipts_bcast_ver_user ON public.broadcast_receipts USING btree (broadcast_id, version_no, user_id);
CREATE UNIQUE INDEX idx_broadcast_versions_bcast_ver ON public.broadcast_versions USING btree (broadcast_id, version);
CREATE UNIQUE INDEX idx_broadcast_versions_bcast_ver_no ON public.broadcast_versions USING btree (broadcast_id, version_no);
CREATE INDEX idx_broadcasts_workspace ON public.broadcasts USING btree (workspace_id, created_at DESC);
CREATE INDEX idx_calls_users ON public.calls USING btree (caller_id, callee_id, started_at DESC);
CREATE INDEX idx_channel_members_user ON public.channel_members USING btree (user_id);
CREATE INDEX idx_channel_messages_chan_seq ON public.channel_messages USING btree (channel_id, seq DESC);
CREATE INDEX idx_channel_messages_parent ON public.channel_messages USING btree (parent_id) WHERE (parent_id IS NOT NULL);
CREATE INDEX idx_channel_references_channel ON public.channel_references USING btree (channel_id, pinned_order);
CREATE INDEX idx_channels_workspace ON public.channels USING btree (workspace_id, is_archived);
CREATE INDEX idx_decisions_channel ON public.decisions USING btree (channel_id, status);
CREATE INDEX idx_departments_workspace ON public.departments USING btree (workspace_id);
CREATE UNIQUE INDEX idx_departments_workspace_code ON public.departments USING btree (workspace_id, code);
CREATE INDEX idx_devices_user ON public.devices USING btree (user_id, status);
CREATE INDEX idx_followups_assignee ON public.followups USING btree (assignee_user_id, status);
CREATE INDEX idx_followups_channel ON public.followups USING btree (channel_id, status);
CREATE INDEX idx_hub_open ON public.hub_items USING btree (user_id, section, created_at DESC) WHERE (resolved_at IS NULL);
CREATE UNIQUE INDEX idx_messages_client ON public.messages USING btree (sender_id, client_id) WHERE (client_id IS NOT NULL);
CREATE INDEX idx_messages_thread ON public.messages USING btree (thread_id, id DESC);
CREATE INDEX idx_mfa_factors_user ON public.mfa_factors USING btree (user_id);
CREATE INDEX idx_offline_queue_recipient ON public.offline_message_queue USING btree (recipient_id, id);
CREATE UNIQUE INDEX idx_policy_entries_ws_scope_key ON public.policy_entries USING btree (workspace_id, scope_type, scope_id, key);
CREATE INDEX idx_policy_group_members_group ON public.policy_group_members USING btree (group_id);
CREATE UNIQUE INDEX idx_reactions_msg_user ON public.reactions USING btree (message_id, user_id);
CREATE INDEX idx_recovery_codes_user ON public.recovery_codes USING btree (user_id);
CREATE INDEX idx_refresh_tokens_device ON public.refresh_tokens USING btree (device_id);
CREATE INDEX idx_relay_push_handles_device ON public.relay_push_handles USING btree (device_id);
CREATE INDEX idx_relay_wake_events_handle ON public.relay_wake_events USING btree (push_handle, created_at DESC);
CREATE UNIQUE INDEX idx_search_docs_doc_type_id ON public.search_docs USING btree (doc_type, doc_id);
CREATE UNIQUE INDEX idx_search_docs_ws_src ON public.search_docs USING btree (workspace_id, source_type, source_id);
CREATE INDEX idx_search_tsv ON public.search_docs USING gin (tsv);
CREATE INDEX idx_sessions_user ON public.sessions USING btree (user_id);
CREATE INDEX idx_thread_members_user ON public.thread_members USING btree (user_id);
CREATE INDEX idx_user_blocks_blocked ON public.user_blocks USING btree (blocked_id);
CREATE UNIQUE INDEX idx_user_roles_unique_global ON public.user_roles USING btree (user_id, role) WHERE (scope_department_id IS NULL);
CREATE UNIQUE INDEX idx_user_roles_unique_scoped ON public.user_roles USING btree (user_id, role, scope_department_id) WHERE (scope_department_id IS NOT NULL);
CREATE INDEX idx_users_external_idp ON public.users USING btree (workspace_id, external_idp_id) WHERE (external_idp_id IS NOT NULL);
CREATE UNIQUE INDEX idx_users_workspace_email ON public.users USING btree (workspace_id, lower((email)::text)) WHERE ((workspace_id IS NOT NULL) AND (email IS NOT NULL));
CREATE UNIQUE INDEX idx_users_workspace_emp_no ON public.users USING btree (workspace_id, employee_no);
CREATE UNIQUE INDEX users_phone_e164_unique ON public.users USING btree (phone_e164) WHERE (phone_e164 IS NOT NULL);
CREATE TRIGGER trg_sync_audit_log BEFORE INSERT OR UPDATE ON public.audit_log FOR EACH ROW EXECUTE FUNCTION public.sync_audit_log_cols();
CREATE TRIGGER trg_sync_broadcast_versions BEFORE INSERT OR UPDATE ON public.broadcast_versions FOR EACH ROW EXECUTE FUNCTION public.sync_broadcast_versions_cols();
CREATE TRIGGER trg_sync_channel_messages BEFORE INSERT OR UPDATE ON public.channel_messages FOR EACH ROW EXECUTE FUNCTION public.sync_channel_messages_cols();
CREATE TRIGGER trg_sync_policy_entries BEFORE INSERT OR UPDATE ON public.policy_entries FOR EACH ROW EXECUTE FUNCTION public.sync_policy_entries_columns();
CREATE TRIGGER trg_sync_search_docs BEFORE INSERT OR UPDATE ON public.search_docs FOR EACH ROW EXECUTE FUNCTION public.sync_search_docs_cols();
ALTER TABLE ONLY public.attachments
    ADD CONSTRAINT attachments_message_id_fkey FOREIGN KEY (message_id) REFERENCES public.channel_messages(id) ON DELETE SET NULL;
ALTER TABLE ONLY public.attachments
    ADD CONSTRAINT attachments_uploader_id_fkey FOREIGN KEY (uploader_id) REFERENCES public.users(id) ON DELETE RESTRICT;
ALTER TABLE ONLY public.attachments
    ADD CONSTRAINT attachments_workspace_id_fkey FOREIGN KEY (workspace_id) REFERENCES public.workspace(id) ON DELETE CASCADE;
ALTER TABLE ONLY public.audit_log
    ADD CONSTRAINT audit_log_actor_device_id_fkey FOREIGN KEY (actor_device_id) REFERENCES public.devices(id) ON DELETE SET NULL;
ALTER TABLE ONLY public.audit_log
    ADD CONSTRAINT audit_log_actor_user_id_fkey FOREIGN KEY (actor_user_id) REFERENCES public.users(id) ON DELETE SET NULL;
ALTER TABLE ONLY public.audit_log
    ADD CONSTRAINT audit_log_workspace_id_fkey FOREIGN KEY (workspace_id) REFERENCES public.workspace(id) ON DELETE CASCADE;
ALTER TABLE ONLY public.auth_providers
    ADD CONSTRAINT auth_providers_workspace_id_fkey FOREIGN KEY (workspace_id) REFERENCES public.workspace(id) ON DELETE CASCADE;
ALTER TABLE ONLY public.break_glass
    ADD CONSTRAINT break_glass_approved_by_fkey FOREIGN KEY (approved_by) REFERENCES public.users(id) ON DELETE RESTRICT;
ALTER TABLE ONLY public.break_glass
    ADD CONSTRAINT break_glass_initiated_by_fkey FOREIGN KEY (initiated_by) REFERENCES public.users(id) ON DELETE SET NULL;
ALTER TABLE ONLY public.break_glass
    ADD CONSTRAINT break_glass_requested_by_fkey FOREIGN KEY (requested_by) REFERENCES public.users(id) ON DELETE RESTRICT;
ALTER TABLE ONLY public.break_glass
    ADD CONSTRAINT break_glass_workspace_id_fkey FOREIGN KEY (workspace_id) REFERENCES public.workspace(id) ON DELETE CASCADE;
ALTER TABLE ONLY public.broadcast_receipts
    ADD CONSTRAINT broadcast_receipts_ack_device_fkey FOREIGN KEY (ack_device) REFERENCES public.devices(id) ON DELETE SET NULL;
ALTER TABLE ONLY public.broadcast_receipts
    ADD CONSTRAINT broadcast_receipts_broadcast_id_fkey FOREIGN KEY (broadcast_id) REFERENCES public.broadcasts(id) ON DELETE CASCADE;
ALTER TABLE ONLY public.broadcast_receipts
    ADD CONSTRAINT broadcast_receipts_device_id_fkey FOREIGN KEY (device_id) REFERENCES public.devices(id) ON DELETE SET NULL;
ALTER TABLE ONLY public.broadcast_receipts
    ADD CONSTRAINT broadcast_receipts_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;
ALTER TABLE ONLY public.broadcast_recipients
    ADD CONSTRAINT broadcast_recipients_broadcast_id_fkey FOREIGN KEY (broadcast_id) REFERENCES public.broadcasts(id) ON DELETE CASCADE;
ALTER TABLE ONLY public.broadcast_recipients
    ADD CONSTRAINT broadcast_recipients_department_id_fkey FOREIGN KEY (department_id) REFERENCES public.departments(id) ON DELETE SET NULL;
ALTER TABLE ONLY public.broadcast_recipients
    ADD CONSTRAINT broadcast_recipients_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;
ALTER TABLE ONLY public.broadcast_templates
    ADD CONSTRAINT broadcast_templates_workspace_id_fkey FOREIGN KEY (workspace_id) REFERENCES public.workspace(id) ON DELETE CASCADE;
ALTER TABLE ONLY public.broadcast_versions
    ADD CONSTRAINT broadcast_versions_broadcast_id_fkey FOREIGN KEY (broadcast_id) REFERENCES public.broadcasts(id) ON DELETE CASCADE;
ALTER TABLE ONLY public.broadcast_versions
    ADD CONSTRAINT broadcast_versions_created_by_fkey FOREIGN KEY (created_by) REFERENCES public.users(id) ON DELETE RESTRICT;
ALTER TABLE ONLY public.broadcast_versions
    ADD CONSTRAINT broadcast_versions_edited_by_fkey FOREIGN KEY (edited_by) REFERENCES public.users(id) ON DELETE SET NULL;
ALTER TABLE ONLY public.broadcasts
    ADD CONSTRAINT broadcasts_created_by_fkey FOREIGN KEY (created_by) REFERENCES public.users(id) ON DELETE SET NULL;
ALTER TABLE ONLY public.broadcasts
    ADD CONSTRAINT broadcasts_sender_id_fkey FOREIGN KEY (sender_id) REFERENCES public.users(id) ON DELETE RESTRICT;
ALTER TABLE ONLY public.broadcasts
    ADD CONSTRAINT broadcasts_workspace_id_fkey FOREIGN KEY (workspace_id) REFERENCES public.workspace(id) ON DELETE CASCADE;
ALTER TABLE ONLY public.calls
    ADD CONSTRAINT calls_callee_id_fkey FOREIGN KEY (callee_id) REFERENCES public.users(id) ON DELETE SET NULL;
ALTER TABLE ONLY public.calls
    ADD CONSTRAINT calls_caller_id_fkey FOREIGN KEY (caller_id) REFERENCES public.users(id) ON DELETE SET NULL;
ALTER TABLE ONLY public.channel_members
    ADD CONSTRAINT channel_members_channel_id_fkey FOREIGN KEY (channel_id) REFERENCES public.channels(id) ON DELETE CASCADE;
ALTER TABLE ONLY public.channel_members
    ADD CONSTRAINT channel_members_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;
ALTER TABLE ONLY public.channel_messages
    ADD CONSTRAINT channel_messages_channel_id_fkey FOREIGN KEY (channel_id) REFERENCES public.channels(id) ON DELETE CASCADE;
ALTER TABLE ONLY public.channel_messages
    ADD CONSTRAINT channel_messages_parent_id_fkey FOREIGN KEY (parent_id) REFERENCES public.channel_messages(id) ON DELETE SET NULL;
ALTER TABLE ONLY public.channel_messages
    ADD CONSTRAINT channel_messages_pinned_by_fkey FOREIGN KEY (pinned_by) REFERENCES public.users(id) ON DELETE SET NULL;
ALTER TABLE ONLY public.channel_messages
    ADD CONSTRAINT channel_messages_reply_to_id_fkey FOREIGN KEY (reply_to_id) REFERENCES public.channel_messages(id) ON DELETE SET NULL;
ALTER TABLE ONLY public.channel_messages
    ADD CONSTRAINT channel_messages_sender_id_fkey FOREIGN KEY (sender_id) REFERENCES public.users(id) ON DELETE RESTRICT;
ALTER TABLE ONLY public.channel_references
    ADD CONSTRAINT channel_references_added_by_fkey FOREIGN KEY (added_by) REFERENCES public.users(id) ON DELETE RESTRICT;
ALTER TABLE ONLY public.channel_references
    ADD CONSTRAINT channel_references_attachment_id_fkey FOREIGN KEY (attachment_id) REFERENCES public.attachments(id) ON DELETE SET NULL;
ALTER TABLE ONLY public.channel_references
    ADD CONSTRAINT channel_references_channel_id_fkey FOREIGN KEY (channel_id) REFERENCES public.channels(id) ON DELETE CASCADE;
ALTER TABLE ONLY public.channel_references
    ADD CONSTRAINT channel_references_created_by_fkey FOREIGN KEY (created_by) REFERENCES public.users(id) ON DELETE SET NULL;
ALTER TABLE ONLY public.channel_references
    ADD CONSTRAINT channel_references_message_id_fkey FOREIGN KEY (message_id) REFERENCES public.channel_messages(id) ON DELETE SET NULL;
ALTER TABLE ONLY public.channel_references
    ADD CONSTRAINT channel_references_pinned_by_fkey FOREIGN KEY (pinned_by) REFERENCES public.users(id) ON DELETE SET NULL;
ALTER TABLE ONLY public.channel_references
    ADD CONSTRAINT channel_references_workspace_id_fkey FOREIGN KEY (workspace_id) REFERENCES public.workspace(id) ON DELETE CASCADE;
ALTER TABLE ONLY public.channels
    ADD CONSTRAINT channels_created_by_fkey FOREIGN KEY (created_by) REFERENCES public.users(id) ON DELETE SET NULL;
ALTER TABLE ONLY public.channels
    ADD CONSTRAINT channels_department_id_fkey FOREIGN KEY (department_id) REFERENCES public.departments(id) ON DELETE SET NULL;
ALTER TABLE ONLY public.channels
    ADD CONSTRAINT channels_workspace_id_fkey FOREIGN KEY (workspace_id) REFERENCES public.workspace(id) ON DELETE CASCADE;
ALTER TABLE ONLY public.credentials
    ADD CONSTRAINT credentials_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;
ALTER TABLE ONLY public.decisions
    ADD CONSTRAINT decisions_channel_id_fkey FOREIGN KEY (channel_id) REFERENCES public.channels(id) ON DELETE CASCADE;
ALTER TABLE ONLY public.decisions
    ADD CONSTRAINT decisions_created_by_fkey FOREIGN KEY (created_by) REFERENCES public.users(id) ON DELETE RESTRICT;
ALTER TABLE ONLY public.decisions
    ADD CONSTRAINT decisions_decided_by_fkey FOREIGN KEY (decided_by) REFERENCES public.users(id) ON DELETE SET NULL;
ALTER TABLE ONLY public.decisions
    ADD CONSTRAINT decisions_message_id_fkey FOREIGN KEY (message_id) REFERENCES public.channel_messages(id) ON DELETE SET NULL;
ALTER TABLE ONLY public.decisions
    ADD CONSTRAINT decisions_owner_id_fkey FOREIGN KEY (owner_id) REFERENCES public.users(id) ON DELETE SET NULL;
ALTER TABLE ONLY public.decisions
    ADD CONSTRAINT decisions_owner_user_id_fkey FOREIGN KEY (owner_user_id) REFERENCES public.users(id) ON DELETE RESTRICT;
ALTER TABLE ONLY public.decisions
    ADD CONSTRAINT decisions_source_message_id_fkey FOREIGN KEY (source_message_id) REFERENCES public.channel_messages(id) ON DELETE SET NULL;
ALTER TABLE ONLY public.decisions
    ADD CONSTRAINT decisions_source_msg_id_fkey FOREIGN KEY (source_msg_id) REFERENCES public.channel_messages(id) ON DELETE SET NULL;
ALTER TABLE ONLY public.decisions
    ADD CONSTRAINT decisions_superseded_by_fkey FOREIGN KEY (superseded_by) REFERENCES public.decisions(id) ON DELETE SET NULL;
ALTER TABLE ONLY public.decisions
    ADD CONSTRAINT decisions_workspace_id_fkey FOREIGN KEY (workspace_id) REFERENCES public.workspace(id) ON DELETE CASCADE;
ALTER TABLE ONLY public.departments
    ADD CONSTRAINT departments_head_user_id_fkey FOREIGN KEY (head_user_id) REFERENCES public.users(id) ON DELETE SET NULL;
ALTER TABLE ONLY public.departments
    ADD CONSTRAINT departments_manager_user_id_fkey FOREIGN KEY (manager_user_id) REFERENCES public.users(id) ON DELETE SET NULL;
ALTER TABLE ONLY public.departments
    ADD CONSTRAINT departments_parent_id_fkey FOREIGN KEY (parent_id) REFERENCES public.departments(id) ON DELETE SET NULL;
ALTER TABLE ONLY public.departments
    ADD CONSTRAINT departments_workspace_id_fkey FOREIGN KEY (workspace_id) REFERENCES public.workspace(id) ON DELETE CASCADE;
ALTER TABLE ONLY public.devices
    ADD CONSTRAINT devices_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;
ALTER TABLE ONLY public.devices
    ADD CONSTRAINT devices_workspace_id_fkey FOREIGN KEY (workspace_id) REFERENCES public.workspace(id) ON DELETE CASCADE;
ALTER TABLE ONLY public.enrollment_tokens
    ADD CONSTRAINT enrollment_tokens_created_by_fkey FOREIGN KEY (created_by) REFERENCES public.users(id) ON DELETE SET NULL;
ALTER TABLE ONLY public.enrollment_tokens
    ADD CONSTRAINT enrollment_tokens_default_group_id_fkey FOREIGN KEY (default_group_id) REFERENCES public.policy_groups(id) ON DELETE SET NULL;
ALTER TABLE ONLY public.enrollment_tokens
    ADD CONSTRAINT enrollment_tokens_target_user_id_fkey FOREIGN KEY (target_user_id) REFERENCES public.users(id) ON DELETE CASCADE;
ALTER TABLE ONLY public.enrollment_tokens
    ADD CONSTRAINT enrollment_tokens_workspace_id_fkey FOREIGN KEY (workspace_id) REFERENCES public.workspace(id) ON DELETE CASCADE;
ALTER TABLE ONLY public.followups
    ADD CONSTRAINT followups_assignee_user_id_fkey FOREIGN KEY (assignee_user_id) REFERENCES public.users(id) ON DELETE RESTRICT;
ALTER TABLE ONLY public.followups
    ADD CONSTRAINT followups_channel_id_fkey FOREIGN KEY (channel_id) REFERENCES public.channels(id) ON DELETE CASCADE;
ALTER TABLE ONLY public.followups
    ADD CONSTRAINT followups_created_by_fkey FOREIGN KEY (created_by) REFERENCES public.users(id) ON DELETE RESTRICT;
ALTER TABLE ONLY public.followups
    ADD CONSTRAINT followups_message_id_fkey FOREIGN KEY (message_id) REFERENCES public.channel_messages(id) ON DELETE SET NULL;
ALTER TABLE ONLY public.followups
    ADD CONSTRAINT followups_owner_id_fkey FOREIGN KEY (owner_id) REFERENCES public.users(id) ON DELETE SET NULL;
ALTER TABLE ONLY public.followups
    ADD CONSTRAINT followups_source_message_id_fkey FOREIGN KEY (source_message_id) REFERENCES public.channel_messages(id) ON DELETE SET NULL;
ALTER TABLE ONLY public.followups
    ADD CONSTRAINT followups_source_msg_id_fkey FOREIGN KEY (source_msg_id) REFERENCES public.channel_messages(id) ON DELETE SET NULL;
ALTER TABLE ONLY public.followups
    ADD CONSTRAINT followups_workspace_id_fkey FOREIGN KEY (workspace_id) REFERENCES public.workspace(id) ON DELETE CASCADE;
ALTER TABLE ONLY public.hub_items
    ADD CONSTRAINT hub_items_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;
ALTER TABLE ONLY public.hub_items
    ADD CONSTRAINT hub_items_workspace_id_fkey FOREIGN KEY (workspace_id) REFERENCES public.workspace(id) ON DELETE CASCADE;
ALTER TABLE ONLY public.legal_holds
    ADD CONSTRAINT legal_holds_created_by_fkey FOREIGN KEY (created_by) REFERENCES public.users(id) ON DELETE RESTRICT;
ALTER TABLE ONLY public.legal_holds
    ADD CONSTRAINT legal_holds_placed_by_fkey FOREIGN KEY (placed_by) REFERENCES public.users(id) ON DELETE SET NULL;
ALTER TABLE ONLY public.legal_holds
    ADD CONSTRAINT legal_holds_released_by_fkey FOREIGN KEY (released_by) REFERENCES public.users(id) ON DELETE RESTRICT;
ALTER TABLE ONLY public.legal_holds
    ADD CONSTRAINT legal_holds_workspace_id_fkey FOREIGN KEY (workspace_id) REFERENCES public.workspace(id) ON DELETE CASCADE;
ALTER TABLE ONLY public.mentions
    ADD CONSTRAINT mentions_mentioned_id_fkey FOREIGN KEY (mentioned_id) REFERENCES public.users(id) ON DELETE CASCADE;
ALTER TABLE ONLY public.mentions
    ADD CONSTRAINT mentions_mentioned_user_id_fkey FOREIGN KEY (mentioned_user_id) REFERENCES public.users(id) ON DELETE CASCADE;
ALTER TABLE ONLY public.mentions
    ADD CONSTRAINT mentions_message_id_fkey FOREIGN KEY (message_id) REFERENCES public.channel_messages(id) ON DELETE CASCADE;
ALTER TABLE ONLY public.message_edits
    ADD CONSTRAINT message_edits_edited_by_fkey FOREIGN KEY (edited_by) REFERENCES public.users(id) ON DELETE RESTRICT;
ALTER TABLE ONLY public.message_edits
    ADD CONSTRAINT message_edits_message_id_fkey FOREIGN KEY (message_id) REFERENCES public.channel_messages(id) ON DELETE CASCADE;
ALTER TABLE ONLY public.messages
    ADD CONSTRAINT messages_reply_to_id_fkey FOREIGN KEY (reply_to_id) REFERENCES public.messages(id) ON DELETE SET NULL;
ALTER TABLE ONLY public.messages
    ADD CONSTRAINT messages_sender_id_fkey FOREIGN KEY (sender_id) REFERENCES public.users(id) ON DELETE CASCADE;
ALTER TABLE ONLY public.messages
    ADD CONSTRAINT messages_thread_id_fkey FOREIGN KEY (thread_id) REFERENCES public.threads(id) ON DELETE CASCADE;
ALTER TABLE ONLY public.mfa_factors
    ADD CONSTRAINT mfa_factors_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;
ALTER TABLE ONLY public.offline_message_queue
    ADD CONSTRAINT offline_message_queue_message_id_fkey FOREIGN KEY (message_id) REFERENCES public.messages(id) ON DELETE CASCADE;
ALTER TABLE ONLY public.offline_message_queue
    ADD CONSTRAINT offline_message_queue_recipient_id_fkey FOREIGN KEY (recipient_id) REFERENCES public.users(id) ON DELETE CASCADE;
ALTER TABLE ONLY public.offline_message_queue
    ADD CONSTRAINT offline_message_queue_thread_id_fkey FOREIGN KEY (thread_id) REFERENCES public.threads(id) ON DELETE CASCADE;
ALTER TABLE ONLY public.policy_entries
    ADD CONSTRAINT policy_entries_updated_by_fkey FOREIGN KEY (updated_by) REFERENCES public.users(id) ON DELETE SET NULL;
ALTER TABLE ONLY public.policy_entries
    ADD CONSTRAINT policy_entries_workspace_id_fkey FOREIGN KEY (workspace_id) REFERENCES public.workspace(id) ON DELETE CASCADE;
ALTER TABLE ONLY public.policy_group_members
    ADD CONSTRAINT policy_group_members_department_id_fkey FOREIGN KEY (department_id) REFERENCES public.departments(id) ON DELETE CASCADE;
ALTER TABLE ONLY public.policy_group_members
    ADD CONSTRAINT policy_group_members_group_id_fkey FOREIGN KEY (group_id) REFERENCES public.policy_groups(id) ON DELETE CASCADE;
ALTER TABLE ONLY public.policy_group_members
    ADD CONSTRAINT policy_group_members_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;
ALTER TABLE ONLY public.policy_groups
    ADD CONSTRAINT policy_groups_workspace_id_fkey FOREIGN KEY (workspace_id) REFERENCES public.workspace(id) ON DELETE CASCADE;
ALTER TABLE ONLY public.policy_signing_keys
    ADD CONSTRAINT policy_signing_keys_workspace_id_fkey FOREIGN KEY (workspace_id) REFERENCES public.workspace(id) ON DELETE CASCADE;
ALTER TABLE ONLY public.policy_versions
    ADD CONSTRAINT policy_versions_published_by_fkey FOREIGN KEY (published_by) REFERENCES public.users(id) ON DELETE SET NULL;
ALTER TABLE ONLY public.policy_versions
    ADD CONSTRAINT policy_versions_workspace_id_fkey FOREIGN KEY (workspace_id) REFERENCES public.workspace(id) ON DELETE CASCADE;
ALTER TABLE ONLY public.reactions
    ADD CONSTRAINT reactions_message_id_fkey FOREIGN KEY (message_id) REFERENCES public.channel_messages(id) ON DELETE CASCADE;
ALTER TABLE ONLY public.reactions
    ADD CONSTRAINT reactions_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;
ALTER TABLE ONLY public.recovery_codes
    ADD CONSTRAINT recovery_codes_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;
ALTER TABLE ONLY public.refresh_tokens
    ADD CONSTRAINT refresh_tokens_device_id_fkey FOREIGN KEY (device_id) REFERENCES public.devices(id) ON DELETE CASCADE;
ALTER TABLE ONLY public.refresh_tokens
    ADD CONSTRAINT refresh_tokens_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;
ALTER TABLE ONLY public.relay_push_handles
    ADD CONSTRAINT relay_push_handles_device_id_fkey FOREIGN KEY (device_id) REFERENCES public.devices(id) ON DELETE CASCADE;
ALTER TABLE ONLY public.relay_push_handles
    ADD CONSTRAINT relay_push_handles_workspace_id_fkey FOREIGN KEY (workspace_id) REFERENCES public.workspace(id) ON DELETE CASCADE;
ALTER TABLE ONLY public.search_docs
    ADD CONSTRAINT search_docs_channel_id_fkey FOREIGN KEY (channel_id) REFERENCES public.channels(id) ON DELETE CASCADE;
ALTER TABLE ONLY public.search_docs
    ADD CONSTRAINT search_docs_workspace_id_fkey FOREIGN KEY (workspace_id) REFERENCES public.workspace(id) ON DELETE CASCADE;
ALTER TABLE ONLY public.service_entitlements
    ADD CONSTRAINT service_entitlements_workspace_id_fkey FOREIGN KEY (workspace_id) REFERENCES public.workspace(id) ON DELETE CASCADE;
ALTER TABLE ONLY public.sessions
    ADD CONSTRAINT sessions_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;
ALTER TABLE ONLY public.thread_members
    ADD CONSTRAINT thread_members_thread_id_fkey FOREIGN KEY (thread_id) REFERENCES public.threads(id) ON DELETE CASCADE;
ALTER TABLE ONLY public.thread_members
    ADD CONSTRAINT thread_members_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;
ALTER TABLE ONLY public.threads
    ADD CONSTRAINT threads_created_by_fkey FOREIGN KEY (created_by) REFERENCES public.users(id) ON DELETE SET NULL;
ALTER TABLE ONLY public.user_blocks
    ADD CONSTRAINT user_blocks_blocked_id_fkey FOREIGN KEY (blocked_id) REFERENCES public.users(id) ON DELETE CASCADE;
ALTER TABLE ONLY public.user_blocks
    ADD CONSTRAINT user_blocks_blocker_id_fkey FOREIGN KEY (blocker_id) REFERENCES public.users(id) ON DELETE CASCADE;
ALTER TABLE ONLY public.user_key_bundles
    ADD CONSTRAINT user_key_bundles_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;
ALTER TABLE ONLY public.user_roles
    ADD CONSTRAINT user_roles_granted_by_fkey FOREIGN KEY (granted_by) REFERENCES public.users(id) ON DELETE SET NULL;
ALTER TABLE ONLY public.user_roles
    ADD CONSTRAINT user_roles_scope_department_id_fkey FOREIGN KEY (scope_department_id) REFERENCES public.departments(id) ON DELETE CASCADE;
ALTER TABLE ONLY public.user_roles
    ADD CONSTRAINT user_roles_scope_dept_id_fkey FOREIGN KEY (scope_dept_id) REFERENCES public.departments(id) ON DELETE CASCADE;
ALTER TABLE ONLY public.user_roles
    ADD CONSTRAINT user_roles_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;
ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_auth_provider_id_fkey FOREIGN KEY (auth_provider_id) REFERENCES public.auth_providers(id) ON DELETE SET NULL;
ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_department_id_fkey FOREIGN KEY (department_id) REFERENCES public.departments(id) ON DELETE SET NULL;
ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_workspace_id_fkey FOREIGN KEY (workspace_id) REFERENCES public.workspace(id) ON DELETE CASCADE;
