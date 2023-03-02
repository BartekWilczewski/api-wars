-- Table: public.users

-- DROP TABLE public.users;

CREATE TABLE public.users
(
    password text COLLATE pg_catalog."default" NOT NULL,
    user_login text COLLATE pg_catalog."default" NOT NULL,
    user_name text COLLATE pg_catalog."default" NOT NULL,
    email text COLLATE pg_catalog."default" NOT NULL
)

TABLESPACE pg_default;

ALTER TABLE public.users
    OWNER to postgres;