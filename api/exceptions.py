from django.http import JsonResponse

def bad_request(request, exception):
    return JsonResponse({'error': 'Bad request'}, status=400)

def permission_denied(request, exception):
    return JsonResponse({'error': 'Permission denied'}, status=403)

def page_not_found(request, exception):
    return JsonResponse({'error': 'Page not found'}, status=404)

def server_error(request):
    return JsonResponse({'error': 'Server error'}, status=500)
