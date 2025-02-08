create table auth_sys.role (
	id serial primary key,
	created_at timestamp default localtimestamp,
	valid_from	timestamp default '2000-01-01 00:00:00.000'::timestamp,
	valid_to	timestamp default '9999-12-31 23:59:59.999'::timestamp,
	code int4 unique,
	name varchar(50) unique not null
);

comment on table auth_sys.role is 'Перечень ролей, доступных пользователям.';

comment on column auth_sys.role.id is 'Идентификатор роли.';
comment on column auth_sys.role.created_at is 'Дата и время создания роли.';
comment on column auth_sys.role.valid_from is 'Дата и время начала действия роли.'; 
comment on column auth_sys.role.valid_to is 'Дата и время окончания действия роли.'; 
comment on column auth_sys.role.code is 'Код роли.'; 
comment on column auth_sys.role.name is 'Наименование роли';

create table auth_sys.user (
	id bigserial primary key,
	created_at timestamp default localtimestamp,
	last_login timestamp default localtimestamp,
	role_code int4,
	login varchar(255) unique not null,
	email varchar(255) unique not null,
	password varchar(60) not null,
	foreign key (role_code) references auth_sys.role (code)
);

insert into auth_sys.user (role_code,login,email,password) select 1,'admin','admin@admin.ru', 'admin'

comment on table auth_sys.user is 'Перечень пользователей.';

comment on column auth_sys.user.id is 'Идентификатор пользователя.';
comment on column auth_sys.user.created_at is 'Дата и время создания пользователя.';
comment on column auth_sys.user.last_login is 'Дата и время последнего захода в систему пользователем.';
comment on column auth_sys.user.role_code is 'Код роли пользователя.';
comment on column auth_sys.user.login is 'Логин пользователя.';
comment on column auth_sys.user.email is 'Электронная почта пользователя.';
comment on column auth_sys.user.password is 'Пароль пользователя.';


create or replace function auth_sys.login_attempt (
	p_login		varchar(255),	--? Логин пользователя;
	p_password	varchar(60)		--? Пароль пользователя;
)
returns setof record as $$
begin
	update auth_sys.user
	set
		last_login = localtimestamp
	where
		login = p_login
		and password = p_password;
	return query
		select
			id,
			role_code
		from auth_sys.user
		where
			login = p_login
			and password = p_password;
end;
$$
language plpgsql;