from flask_admin.contrib.sqla import ModelView
from flask_login import current_user
from flask import redirect
from flask_admin import AdminIndexView
import os
from dotenv import load_dotenv

load_dotenv()


VUE_BASE_URL = os.getenv("VUE_BASE_URL")
class CustomModelView(ModelView):
    def is_accessible(self):
        return current_user.is_authenticated and current_user.has_role("admin")
    
    def inaccessible_callback(self, name, **kwargs):
        # Redirect to the login page if the user doesn't have access
        return redirect(f"{VUE_BASE_URL}/login")

class HomeAdminView(AdminIndexView):
    def is_accessible(self):
        return current_user.is_authenticated and current_user.has_role("admin")
    
    def inaccessible_callback(self, name, **kwargs):
        # Redirect to the login page if the user doesn't have access
        return redirect(f"{VUE_BASE_URL}/login")