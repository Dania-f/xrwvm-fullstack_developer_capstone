from django.shortcuts import redirect
from django.contrib.auth.models import User
from django.contrib.auth import login, logout, authenticate
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
import json
import logging

# Set up logging
logger = logging.getLogger(__name__)


@csrf_exempt
def login_user(request):
    if request.method == "POST":
        try:
            data = json.loads(request.body.decode("utf-8"))
            username = data.get('userName')
            password = data.get('password')

            logger.info(f"Login attempt for user: {username}")

            user = authenticate(username=username, password=password)
            if user is not None:
                login(request, user)
                logger.info(f"User '{username}' authenticated successfully.")
                return JsonResponse({"userName": username, "status": "Authenticated"})
            else:
                logger.warning(f"Invalid login for user: {username}")
                return JsonResponse({"userName": username, "error": "Invalid credentials"}, status=401)

        except json.JSONDecodeError:
            logger.exception("Invalid JSON format.")
            return JsonResponse({"error": "Invalid JSON format"}, status=400)
        except Exception as e:
            logger.exception("Unexpected error during login.")
            return JsonResponse({"error": str(e)}, status=500)

    return JsonResponse({"error": "POST request required"}, status=400)
@csrf_exempt
def logout_request(request):
    if request.method == "POST":
        logout(request)
        return JsonResponse({"userName": "", "status": "Logged out"})
    return JsonResponse({"error": "POST request required"}, status=400)

@csrf_exempt
def registration(request):
    if request.method == "POST":
        try:
            data = json.loads(request.body.decode("utf-8"))
            username = data.get("userName")
            password = data.get("password")

            if User.objects.filter(username=username).exists():
                return JsonResponse({"error": "Username already exists"}, status=400)

            user = User.objects.create_user(username=username, password=password)
            login(request, user)

            return JsonResponse({"userName": username, "status": "Registered"})

        except json.JSONDecodeError:
            return JsonResponse({"error": "Invalid JSON format"}, status=400)
        except Exception as e:
            return JsonResponse({"error": str(e)}, status=500)

    return JsonResponse({"error": "POST request required"}, status=400)
