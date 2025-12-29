from flask import Blueprint, render_template, flash, url_for, redirect, request
from config import db, Post, roles_required, security_logger
from posts.forms import PostForm
from sqlalchemy import desc
from flask_login import current_user, login_required

posts_bp = Blueprint("posts", __name__, template_folder="templates")


@posts_bp.route("/create", methods=("GET", "POST"))
@login_required
@roles_required("end_user")
def create():
    form = PostForm()

    if form.validate_on_submit():
        new_post = Post(title=form.title.data, body=form.body.data, userid=current_user.get_id())
        new_post.encrypt_post(current_user.get_encryption_key())
        db.session.add(new_post)
        db.session.commit()

        flash("Post Created!", category="success")

        security_logger.info(f"Post created: Email={current_user.email}, Role={current_user.role},"
            f" PostID={new_post.id}, IP={request.remote_addr}")

        return redirect(url_for("posts.posts"))

    return render_template("posts/create.html", form=form)


@posts_bp.route("/posts")
@login_required
@roles_required("end_user")
def posts():
    all_posts = Post.query.order_by(desc("id")).all()

    for post in all_posts:
        post.decrypt_post(post.user.get_encryption_key())

    return render_template("posts/posts.html", posts=all_posts)


@posts_bp.route("/<int:id>/update", methods=("GET", "POST"))
@login_required
@roles_required("end_user")
def update(id):
    post_to_update = Post.query.filter_by(id=id).first()

    if post_to_update.userid != current_user.id:
        flash("You can't update another users post!", "danger")
        return redirect(url_for("posts.posts"))
    if not post_to_update:
        return redirect(url_for("posts.posts"))

    post_to_update.decrypt_post(post_to_update.user.get_encryption_key())
    form = PostForm()

    if form.validate_on_submit():
        post_to_update.update(title=form.title.data, body=form.body.data)
        flash("Post Updated!", category="success")
        security_logger.info(
            f"Post updated: Email={current_user.email}, Role={current_user.role}, PostID={post_to_update.id}, "
            f"PostAuthorEmail={post_to_update.user.email}, IP={request.remote_addr}")
        return redirect(url_for("posts.posts"))

    form.title.data = post_to_update.title
    form.body.data = post_to_update.body



    return render_template("posts/update.html", form=form)


@posts_bp.route("/<int:id>/delete")
@login_required
@roles_required("end_user")
def delete(id):
    post_to_delete = Post.query.filter_by(id=id).first()

    if post_to_delete.userid != current_user.id:
        flash("You can't delete another users post!", "danger")
        return redirect(url_for("posts.posts"))

    db.session.delete(post_to_delete)
    db.session.commit()

    flash("Post deleted", category="success")

    security_logger.info(f"Post deleted: Email={current_user.email}, Role={current_user.role}, PostID={post_to_delete.id}, "
                         f"PostAuthorEmail={post_to_delete.user.email}, IP={request.remote_addr}")

    return redirect(url_for("posts.posts"))
