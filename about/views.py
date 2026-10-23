"""Views for the about app: About page and Contact form."""
from django.contrib import messages
from django.urls import reverse_lazy
from django.views.generic import FormView, TemplateView

from .forms import ContactForm
from .models import TeamMember


class AboutView(TemplateView):
    template_name = "about/about.html"

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        # ``TeamMember.Meta.ordering`` (display_order, name) drives the grid
        # order; only active members are shown. Empty when none are added yet.
        context["team_members"] = TeamMember.objects.filter(is_active=True)
        return context


class ContactView(FormView):
    template_name = "about/contact.html"
    form_class = ContactForm
    success_url = reverse_lazy("about:contact")

    def form_valid(self, form):
        # Link the message to the signed-in user when present. This is set from
        # the authenticated request only - never from POST data - so a sender
        # cannot attribute their message to someone else's account.
        if self.request.user.is_authenticated:
            form.instance.user = self.request.user
        try:
            # FormView does not auto-save; persist explicitly. A DB error must
            # not be reported as success.
            form.save()
        except Exception:  # noqa: BLE001 - never claim success if saving failed
            messages.error(
                self.request,
                "We couldn't save your message right now. Please try again later.",
            )
            return self.form_invalid(form)
        messages.success(
            self.request,
            "Thanks for reaching out! Our team will get back to you shortly.",
        )
        return super().form_valid(form)
