from __future__ import annotations

import sqlite3
from typing import Optional
from flask import (
    Blueprint,
    flash,
    g,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from werkzeug.security import check_password_hash

from shared.config import DB_PATH
from shared.db import get_db

# Flask-Login imports with fallback
try:
    from flask_login import (
        LoginManager,
        UserMixin,
        login_user,
        logout_user,
        login_required,
        current_user,
    )
except ImportError:
    from functools import wraps

    class UserMixin:
        """Standard Flask-Login UserMixin fallback."""
        @property
        def is_authenticated(self) -> bool:
            return True

        @property
        def is_active(self) -> bool:
            return True

        @property
        def is_anonymous(self) -> bool:
            return False

        def get_id(self) -> str:
            return str(getattr(self, "id", ""))

    class AnonymousUser:
        is_authenticated = False
        is_active = False
        is_anonymous = True
        username = "Guest"
        role = "guest"
        id = None

        def get_id(self) -> None:
            return None

    class _CurrentUserProxy:
        def __getattr__(self, name):
            user = getattr(g, "_current_user", None)
            if user is None:
                user = AnonymousUser()
            return getattr(user, name)

        def __bool__(self) -> bool:
            user = getattr(g, "_current_user", None)
            return bool(user and user.is_authenticated)

    current_user = _CurrentUserProxy()

    def login_user(user, remember: bool = False) -> bool:
        session["_user_id"] = str(user.get_id())
        if remember:
            session.permanent = True
        g._current_user = user
        return True

    def logout_user() -> bool:
        session.pop("_user_id", None)
        g._current_user = AnonymousUser()
        return True

    def login_required(func):
        @wraps(func)
        def decorated_view(*args, **kwargs):
            if not current_user.is_authenticated:
                return redirect(url_for("auth.login", next=request.url if request.method == "GET" else None))
            return func(*args, **kwargs)
        return decorated_view

    class LoginManager:
        def __init__(self, app=None) -> None:
            self.login_view = "auth.login"
            self._user_loader = None
            if app:
                self.init_app(app)

        def init_app(self, app) -> None:
            @app.before_request
            def load_user_from_session():
                user_id = session.get("_user_id")
                if user_id and self._user_loader:
                    g._current_user = self._user_loader(user_id)
                else:
                    g._current_user = AnonymousUser()

            @app.context_processor
            def inject_current_user():
                return dict(current_user=current_user)

        def user_loader(self, callback):
            self._user_loader = callback
            return callback


class User(UserMixin):
    """Authenticated user representation for dashboard session management."""

    def __init__(self, id: int | str, username: str, role: str = "user") -> None:
        self.id = str(id)
        self.username = username
        self.role = role

    def get_id(self) -> str:
        return str(self.id)

    @property
    def is_admin(self) -> bool:
        return self.role.lower() == "admin"


auth_bp = Blueprint("auth", __name__)


def get_user_by_id(user_id: str | int, db_path: str = DB_PATH) -> Optional[User]:
    """Retrieve user record by database primary key."""
    try:
        with get_db(db_path) as conn:
            row = conn.execute("SELECT id, username, role FROM users WHERE id = ?", (user_id,)).fetchone()
            if row:
                return User(id=row["id"], username=row["username"], role=row["role"])
    except Exception:
        pass
    return None


def get_user_by_username(username: str, db_path: str = DB_PATH) -> Optional[sqlite3.Row]:
    """Retrieve full user row by username."""
    try:
        with get_db(db_path) as conn:
            return conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    except Exception:
        return None


@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    """Login route with credential validation against users database table."""
    # Redirect already-authenticated users to dashboard
    if current_user.is_authenticated:
        return redirect(url_for("index"))

    error: Optional[str] = None
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        user_row = get_user_by_username(username)
        if user_row and check_password_hash(user_row["password_hash"], password):
            user = User(id=user_row["id"], username=user_row["username"], role=user_row["role"])
            # Set permanent session and remember cookie for persistent login
            session.permanent = True
            login_user(user, remember=True)
            flash(f"Welcome back, {user.username}!", "success")
            next_url = request.args.get("next")
            # Protect against open redirect vulnerabilities
            if next_url and next_url.startswith("/"):
                return redirect(next_url)
            return redirect(url_for("index"))
        else:
            error = "Invalid username or password. Please verify credentials."
            flash(error, "error")

    return render_template("login.html", error=error)


@auth_bp.route("/logout")
@login_required
def logout():
    """Sign out the current user session and redirect to login."""
    logout_user()
    flash("You have been signed out successfully.", "info")
    return redirect(url_for("auth.login"))


def init_auth(app, db_path: str = DB_PATH) -> LoginManager:
    """Initialize login manager and register authentication blueprint."""
    login_manager = LoginManager()
    login_manager.login_view = "auth.login"
    login_manager.login_message = "Please sign in to access the security dashboard."
    login_manager.login_message_category = "error"

    @login_manager.user_loader
    def user_loader(user_id: str) -> Optional[User]:
        return get_user_by_id(user_id, db_path=db_path)

    login_manager.init_app(app)
    app.register_blueprint(auth_bp)

    return login_manager

