from flask import Blueprint, render_template, redirect, url_for, flash, request
from flask_login import login_user, logout_user, login_required, current_user
from app.models.database import db, User, AuditLog
from datetime import datetime

bp = Blueprint('auth', __name__, url_prefix='/auth')

@bp.route('/login', methods=['GET', 'POST'])
def login():
    """Bypass login page completely - automatically authenticate as admin"""
    admin_user = User.query.filter_by(username='admin').first()
    if admin_user:
        login_user(admin_user, remember=True)
    return redirect(url_for('dashboard.index'))

@bp.route('/logout')
def logout():
    """Logout redirect - keep user logged in as admin"""
    admin_user = User.query.filter_by(username='admin').first()
    if admin_user:
        login_user(admin_user, remember=True)
    return redirect(url_for('dashboard.index'))
    # Log audit
    audit = AuditLog(
        user_id=current_user.id,
        action='LOGOUT',
        ip_address=request.remote_addr
    )
    db.session.add(audit)
    db.session.commit()
    
    logout_user()
    flash('You have been logged out', 'success')
    return redirect(url_for('auth.login'))

@bp.route('/change-password', methods=['GET', 'POST'])
@login_required
def change_password():
    """Change password"""
    if request.method == 'POST':
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')
        
        if not current_user.check_password(current_password):
            flash('Current password is incorrect', 'danger')
        elif new_password != confirm_password:
            flash('New passwords do not match', 'danger')
        elif len(new_password) < 6:
            flash('Password must be at least 6 characters', 'danger')
        else:
            current_user.set_password(new_password)
            db.session.commit()
            
            # Log audit
            audit = AuditLog(
                user_id=current_user.id,
                action='PASSWORD_CHANGE',
                ip_address=request.remote_addr
            )
            db.session.add(audit)
            db.session.commit()
            
            flash('Password changed successfully', 'success')
            return redirect(url_for('dashboard.index'))
    
    return render_template('change_password.html')
