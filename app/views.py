"""
Definition of views.
"""

from datetime import datetime
from django.shortcuts import render
from django.http import HttpRequest
from django.shortcuts import render, redirect
from django.utils.timezone import now
from .models import Reports, EvidentImages, EvidentVideos
from django.contrib.auth.views import LoginView
from django.shortcuts import redirect
from django.contrib.auth import authenticate, login
from django.contrib import messages
from django import forms
from .models import Users
from django.db import IntegrityError
from django.views.decorators.http import require_http_methods
from django.shortcuts import get_object_or_404
from app.models import RankChangeRequests, RegionChangeRequests
from .models import CaseReports
from django.contrib.auth.decorators import login_required
from django.views.decorators.http import require_POST
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth.hashers import check_password
from django.db import transaction
from app.decorators import session_login_required, session_role_required
from app.utils.upload_validators import (
    validate_total_size,
    validate_file,
)
from django.core.exceptions import ValidationError

@session_login_required
@session_role_required(['Admin', 'Superintendent', 'Director General'])
def review_rank_changes_admin(request):
    requests = RankChangeRequests.objects.filter(confirmation='accepted', managed=False)

    if request.method == 'POST':
        request_id = request.POST.get('request_id')
        action = request.POST.get('action')  # 'apply' or 'reject'

        req = get_object_or_404(RankChangeRequests, id=request_id)

        if action == 'apply':
            user = req.name
            user.rank = req.updaterank
            user.save()
            req.managed = True
            req.save()
            messages.success(request, f"Rank updated for user {user.username}.")
        elif action == 'reject':
            req.delete()
            messages.warning(request, "Rank change request rejected and deleted.")

        return redirect('admin_requests')

    return render(request, 'app/admin_requests.html', {'requests': requests})

@session_login_required
@session_role_required(['Admin', 'Superintendent', 'Director General'])
def review_region_changes_admin(request):
    if request.method == 'POST':
        request_id = request.POST.get('request_id')
        action = request.POST.get('action')
        req = get_object_or_404(RegionChangeRequests, id=request_id)

        if action == 'apply':
            # Parse update_location into state, city, station
            try:
                state, city, station = [x.strip() for x in req.update_location.split(',')]
                user = req.name
                user.state = state
                user.city = city
                user.station = station
                user.save()
                req.delete()
                messages.success(request, 'Region change applied successfully.')
            except Exception as e:
                messages.error(request, f'Error: {e}')
        elif action == 'reject':
            req.delete()
            messages.info(request, 'Region change request rejected.')

        return redirect('admin_requests')

    # GET: show pending accepted requests (approved by higher ranks)
    region_requests = RegionChangeRequests.objects.filter(confirmation='accepted')
    context = {
        'region_requests': region_requests,
    }
    return render(request, 'app/admin_requests.html', context)

@session_login_required
def request_region_change(request):
    if request.method == 'POST' and request.session.get('user_id'):
        user_id = request.session['user_id']
        user = Users.objects.get(id=user_id)

        state = request.POST.get('state')
        city = request.POST.get('city')
        station = request.POST.get('station')

        current_location = f"{user.state},{user.city},{user.station}"
        update_location = f"{state},{city},{station}"

        RegionChangeRequests.objects.create(
            userid=user_id,
            name=user.username,
            policeid=user.policeid,
            rank=user.rank,
            currentlocation=current_location,
            updatelocation=update_location,
            confirmation='Pending'
        )
        messages.success(request, 'Region change request submitted.')
    return redirect('user_profile1')

@session_login_required
def request_rank_change(request):
    if request.method == 'POST' and request.session.get('user_id'):
        user_id = request.session['user_id']
        new_rank = request.POST.get('new_rank')
        user = Users.objects.get(id=user_id)

        RankChangeRequests.objects.create(
            userid=user_id,
            name=user.username,
            policeid=user_id,
            state=user.state,
            city=user.city,
            station=user.station,
            currentrank=user.rank,
            updaterank=new_rank,
            confirmation='Pending'
        )
        messages.success(request, 'Rank change request submitted.')
    return redirect('user_profile1')

def user_profile1(request):
    username = request.session.get('username')
    try:
        user = Users.objects.get(username=username)
    except Users.DoesNotExist:
        user = None

    return render(request, 'app/user_profile1.html', {'user': user})

@session_login_required
def update_case(request, case_id):
    username = request.session.get('username')
    case = get_object_or_404(CaseReports, id=case_id, officer=username)

    if request.method == 'POST':
        files = request.FILES.getlist('evidence_files')

        try:
            validate_total_size(files, max_mb=50)
        except ValidationError as e:
            messages.error(request, str(e))
            return redirect(request.path)

        accepted = []
        rejected = []

        for f in files:
            try:
                mime = validate_file(f)
                accepted.append((f, mime))
            except ValidationError as e:
                rejected.append(str(e))

        if not accepted:
            messages.error(request, "All uploaded files were invalid.")
            return redirect(request.path)

        with transaction.atomic():
            case.suspects = request.POST.get('suspects')
            case.culprit = request.POST.get('culprit')
            case.casedescription = request.POST.get('casedescription')
            case.confirm = request.POST.get('confirm')
            case.save()

            report = Reports.objects.get(id=case.reportid)

            for f, mime in accepted:
                if mime.startswith('image/'):
                    EvidentImages.objects.create(image=f, cid=report)
                elif mime.startswith('video/'):
                    EvidentVideos.objects.create(video=f, cid=report)

        for msg in rejected:
            messages.warning(request, msg)

        messages.success(
            request,
            f"{len(accepted)} file(s) uploaded successfully."
        )

        return redirect('manage_cases')

    return render(request, 'app/update_case.html', {'case': case})


@session_login_required
@require_POST
def take_case(request):
    username = request.session.get('username')
    report_id=request.POST.get('report_id')
    if not username:
        return redirect('login')

    try:
        user = Users.objects.get(username=username)
        report = Reports.objects.get(id=report_id)

        # Create a new CaseReport for the taken case
        CaseReports.objects.create(
            reportid=report.id,
            state=user.state,
            city=user.city,
            station=user.station,
            officer=username,
            confirm='In Progress'
        )

        # Update the status in Reports table
        report.status = 'Taken'
        report.save()

    except (Users.DoesNotExist, Reports.DoesNotExist):
        messages.error(request, "Unable to take the case. User or Report not found.")

    return redirect('assigned_cases')

def manage_cases(request):
    username = request.session.get('username')

    if not username:
        return redirect('login')

    # Filter CaseReports where the logged-in user is the officer
    cases = CaseReports.objects.filter(officer=username)

    context = {
        'cases': cases
    }
    return render(request, 'app/manage_cases.html', context)

def assigned_cases(request):
    user_id = request.session.get('user_id')

    if not user_id:
        return redirect('login')

    try:
        user = Users.objects.get(id=user_id)
    except Users.DoesNotExist:
        return redirect('login')

    # Reports assigned to this user
    assigned = Reports.objects.filter(assignedpoliceid=user.id)

    # Taken cases already handled by this user (status = 'Taken')
    taken = Reports.objects.filter(assignedpoliceid=user.id, status='Taken')

    context = {
        'assigned_cases': assigned.exclude(status='Taken'),
        'taken_cases': taken
    }

    return render(request, 'app/assigned_cases.html', context)

def regional_reports(request):
    # Get current user info
    state = request.session.get('state')
    city = request.session.get('city')
    station = request.session.get('station')

    # Fetch all reports from the same state
    reports = Reports.objects.filter(regionname=state, assignedpoliceid=None)

    # Fetch eligible lower-rank officers in same location
    eligible_officers = Users.objects.filter(
        state=state,
        city=city,
        station=station,
        rank__in=['Constable', 'Sub-Inspector', 'Inspector']
    )

    context = {
        'reports': reports,
        'officers': eligible_officers
    }
    return render(request, 'app/regional_reports.html', context)

@session_login_required
@require_POST
def assign_case(request):
    report_id = request.POST.get('report_id')
    officer_username = request.POST.get('officer')

    if report_id and officer_username:
        try:
            report = Reports.objects.get(id=report_id)
            report.assignedpoliceid = officer_username
            report.save()
            messages.success(request, "Case successfully assigned.")
        except Reports.DoesNotExist:
            messages.error(request, "Report not found.")
    else:
        messages.error(request, "Invalid data submitted.")

    return redirect('regional_reports')

@session_login_required
@session_role_required(['Admin', 'Superintendent', 'Director General'])
def status_change_requests(request):
    if 'user_id' not in request.session:
        return redirect('login')

    user_state = request.session.get('state')
    user_city = request.session.get('city')
    user_station = request.session.get('station')

    region_requests = []
    all_region_requests = RegionChangeRequests.objects.filter(confirmation='Pending')
    for req in all_region_requests:
        if req.updatelocation:
            try:
                u_state, u_city, u_station = [x.strip() for x in req.updatelocation.split(',')]
                if u_state == user_state and u_city == user_city and u_station == user_station:
                    region_requests.append(req)
            except ValueError:
                continue

    rank_requests = RankChangeRequests.objects.filter(
        confirmation='Pending',
        state=user_state,
        city=user_city,
        station=user_station
    )

    context = {
        'region_requests': region_requests,
        'rank_requests': rank_requests,
    }
    return render(request, 'app/status_change_requests.html', context)

@session_login_required
@session_role_required(['Admin', 'Superintendent', 'Director General'])
def process_change_request(request, request_type, request_id, action):
    if request.method == 'POST':
        if request_type == 'region':
            req = get_object_or_404(RegionChangeRequests, id=request_id)
            if action == 'accept':
                req.confirmation = 'accepted'
                req.save()
            elif action == 'reject':
                req.delete()
        elif request_type == 'rank':
            req = get_object_or_404(RankChangeRequests, id=request_id)
            if action == 'accept':
                req.confirmation = 'accepted'
                req.save()
            elif action == 'reject':
                req.delete()
        return redirect('status_change_requests')
    else:
        return redirect('status_change_requests')

def user_profile(request):
    username = request.session.get('username')
    try:
        user = Users.objects.get(username=username)
    except Users.DoesNotExist:
        return redirect('login')  # fallback if something goes wrong

    return render(request, 'app/user_profile.html', {'user': user})

def regional_reports1(request):
    # Get the logged-in user's username from the session
    username = request.session.get('username')

    if not username:
        return redirect('login')  # If not logged in, redirect to login page

    # Fetch the user's region (state)
    try:
        user = Users.objects.get(username=username)
        user_state = user.state
    except Users.DoesNotExist:
        user_state = None

    # Fetch all reports that match the user's state
    reports = Reports.objects.filter(regionname=user_state) if user_state else []

    context = {
        'reports': reports
    }
    return render(request, 'app/regional_reports1.html', context)

def user_dashboard(request):
    if 'user_id' not in request.session:
        return redirect('login')

    username = request.session.get('username')
    rank = request.session.get('rank')

    context = {
        'username': username,
        'rank': rank
    }

    return render(request, 'app/user_dashboard.html', context)

def user_dashboard1(request):
    # Check if the user is logged in (session exists)
    if 'user_id' not in request.session:
        return redirect('login')  # Redirect to login if not logged in

    # Optional: you can get more session info if you want
    username = request.session.get('username')
    rank = request.session.get('rank')

    context = {
        'username': username,
        'rank': rank,
    }

    return render(request, 'app/user_dashboard1.html', context)

def regional_reports1(request):
    username = request.session.get('username')
    if username:
        try:
            user = Users.objects.get(username=username)
            user_state = user.state
            reports = Reports.objects.filter(regionname=user_state)
            return render(request, 'app/regional_reports1.html', {'reports': reports})
        except Users.DoesNotExist:
            return redirect('login')
    else:
        return redirect('login')

@session_login_required
@session_role_required(['Admin', 'Superintendent', 'Director General'])
def admin_requests(request):
    if request.method == 'POST':
        request_type = request.POST.get('request_type')
        request_id = request.POST.get('request_id')
        action = request.POST.get('action')

        if request_type == 'rank':
            req = get_object_or_404(RankChangeRequests, id=request_id)
            if action == 'apply':
                user = Users.objects.get(id=req.userid)
                user.rank = req.updaterank
                user.save()
                req.delete()
            elif action == 'reject':
                req.delete()

        elif request_type == 'region':
            req = get_object_or_404(RegionChangeRequests, id=request_id)
            if action == 'apply':
                user = Users.objects.get(id=req.userid)
                state, city, station = req.updatelocation.split(',')
                user.state, user.city, user.station = state.strip(), city.strip(), station.strip()
                user.save()
                req.delete()
            elif action == 'reject':
                req.delete()

        return redirect('admin_requests')

    # GET: Show accepted requests only
    rank_requests = RankChangeRequests.objects.filter(confirmation='accepted')
    region_requests = RegionChangeRequests.objects.filter(confirmation='accepted')

    return render(request, 'app/admin_requests.html', {
        'rank_requests': rank_requests,
        'region_requests': region_requests
    })

@session_login_required
@session_role_required(['Admin', 'Superintendent', 'Director General'])
def delete_user(request):
    if request.method == 'POST':
        user_id = request.POST.get('user_id')
        user = get_object_or_404(Users, id=int(user_id))
        user.delete()
    return redirect('admin_users')

@session_login_required
@session_role_required(['Admin', 'Superintendent', 'Director General'])
def edit_user(request):
    if request.method == 'POST':
        user_id = request.POST.get('user_id')
        user = get_object_or_404(Users, id=user_id)

        user.username = request.POST.get('username')
        user.policeid = request.POST.get('policeid')
        user.rank = request.POST.get('rank')
        user.email = request.POST.get('email')
        user.state = request.POST.get('state')
        user.city = request.POST.get('city')
        user.station = request.POST.get('station')
        
        user.save()
        return redirect('admin_users')  # Redirect to the user listing page

@require_http_methods(["GET", "POST"])
@session_login_required
@session_role_required(['Admin', 'Superintendent', 'Director General'])
def admin_users(request):
    """
    GET  -> render the page with the users table
    POST -> process the modal 'Add User' form
    """

    # 1️⃣  Handle the Add‑User form submission
    if request.method == "POST":
        username   = request.POST.get("username", "").strip()
        password   = request.POST.get("password", "").strip()
        email      = request.POST.get("email", "").strip()
        police_id  = request.POST.get("police_id", "").strip()
        rank       = request.POST.get("rank")
        state      = request.POST.get("state")
        city       = request.POST.get("city")
        station    = request.POST.get("station")

        # Basic validation (expand as you like)
        if not username or not password:
            messages.error(request, "Username and password are required.")
        elif Users.objects.filter(username=username).exists():
            messages.error(request, "Username already exists.")
        elif Users.objects.filter(email=email).exists():
            messages.error(request, "E‑mail already exists.")
        else:
            try:
                Users.objects.create(
                    username   = username,
                    password   = password,
                    email      = email,
                    policeid   = police_id or None,
                    rank       = rank,
                    state      = state,
                    city       = city,
                    station    = station,
                )
                messages.success(request, "User added successfully!")
                return redirect("admin_users")          # PRG pattern
            except IntegrityError:
                messages.error(request, "Database error—user not created.")

    # 2️⃣  Always fetch current users for the DataTable
    users_qs = Users.objects.all().order_by("id")

    return render(
        request,
        "app/admin_users.html",          # template we built with modal
        {"users": users_qs},
    )

@session_login_required
@session_role_required(['Admin', 'Superintendent', 'Director General'])
def admin_reports(request):
    reports = Reports.objects.all().order_by('-reportdate')  # Show newest first
    context = {
        'reports': reports
    }
    return render(request, 'app/admin_reports.html', context)


class CustomLoginForm(forms.Form):
    username = forms.CharField()
    password = forms.CharField(widget=forms.PasswordInput)

    def __init__(self, *args, **kwargs):
        self.request = kwargs.pop('request', None)  # 👈 Accept and store request
        super().__init__(*args, **kwargs)

class CustomLoginView(LoginView):
    form_class = CustomLoginForm
    template_name = 'app/login.html'

    def form_valid(self, form):
        username = form.cleaned_data.get('username')
        password = form.cleaned_data.get('password')
        remember_me = form.cleaned_data.get('remember_me', False)

        
        # Authenticate using custom backend (hashed passwords)
        user = authenticate(self.request, username=username, password=password)

        if user is None:
            messages.error(self.request, "Invalid login credentials")
            return self.form_invalid(form)

        # ♻️ REQUIRED: login() stores the user in Django's session
        login(self.request, user)

        # Set session expiry (remember me)
        if not remember_me:
            self.request.session.set_expiry(0)        # expires on browser close
        else:
            self.request.session.set_expiry(1209600)  # 2 weeks

        # Store extra session data
        self.request.session['user_id'] = user.id
        self.request.session['username'] = user.username
        self.request.session['state'] = user.state
        self.request.session['city'] = user.city
        self.request.session['station'] = user.station
        self.request.session['rank'] = user.rank

        # Redirect based on rank
        rank = getattr(user, 'rank', None)

        if rank in ['Constable', 'Sub-Inspector', 'Inspector']:
            return redirect('user_dashboard1')

        elif rank in ['Superintendent', 'Director General']:
            return redirect('user_dashboard')

        elif rank == 'Admin':
            return redirect('admin_reports')

        # Fallback redirect (never return None)
        return redirect('home')

def report_crime(request):
    if request.method == 'POST':
        files = request.FILES.getlist('evidence_files')

        # 1️⃣ total-size check still applies to ALL files
        try:
            validate_total_size(files, max_mb=50)
        except ValidationError as e:
            messages.error(request, str(e))
            return redirect('report_crime')

        accepted = []
        rejected = []

        for f in files:
            try:
                mime = validate_file(f)
                accepted.append((f, mime))
            except ValidationError as e:
                rejected.append(str(e))

        if not accepted:
            messages.error(request, "All uploaded files were invalid.")
            return redirect('report_crime')

        with transaction.atomic():
            report = Reports.objects.create(
                regionname=request.POST.get('region'),
                crimetype=request.POST.get('crime_type'),
                description=request.POST.get('description'),
                reportdate=now()
            )

            for f, mime in accepted:
                if mime.startswith('image/'):
                    EvidentImages.objects.create(image=f, cid=report)
                elif mime.startswith('video/'):
                    EvidentVideos.objects.create(video=f, cid=report)

        if rejected:
            for msg in rejected:
                messages.warning(request, msg)

        messages.success(
            request,
            f"{len(accepted)} file(s) uploaded successfully."
        )

        return redirect('home')

    return render(request, 'app/report_crime.html')


def home(request):
    """Renders the home page."""
    assert isinstance(request, HttpRequest)
    return render(
        request,
        'app/index.html',
        {
            'title':'Home Page',
            'year':datetime.now().year,
        }
    )

def contact(request):
    """Renders the contact page."""
    assert isinstance(request, HttpRequest)
    return render(
        request,
        'app/contact.html',
        {
            'title':'Contact',
            'message':'Your contact page.',
            'year':datetime.now().year,
        }
    )

def about(request):
    """Renders the about page."""
    assert isinstance(request, HttpRequest)
    return render(
        request,
        'app/about.html',
        {
            'title':'About',
            'message':'Your application description page.',
            'year':datetime.now().year,
        }
    )
