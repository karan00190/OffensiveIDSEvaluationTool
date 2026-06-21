# miat_django/urls.py  (project-level — not the scanner app)
# ─────────────────────────────────────────────────────────────────────────────
#  Root URL configuration.
#  include() delegates everything under a prefix to another urls.py file.
# ─────────────────────────────────────────────────────────────────────────────

from django.contrib import admin
from django.urls    import path, include
from django.contrib.auth import views as auth_views
from django.conf          import settings
from django.conf.urls.static import static

urlpatterns = [
    # Django admin panel
    path('admin/', admin.site.urls),

    # Built-in login / logout pages
    # Django provides these views — you just need the templates
    path('accounts/login/',  auth_views.LoginView.as_view(
        template_name='scanner/login.html'), name='login'),
    path('accounts/logout/', auth_views.LogoutView.as_view(
        next_page='login'), name='logout'),

    # Everything else → scanner app
    # '' means the scanner app handles the root URL /
    path('', include('scanner.urls', namespace='scanner')),
] + static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)