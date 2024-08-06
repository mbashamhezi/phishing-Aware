import requests
from django.shortcuts import render
from django.http import JsonResponse

VIRUSTOTAL_API_KEY = 'd156afe757870c7db2b3e6c11cd428342156f1ac388527d1b8d771b2d9a4b455'

def home(request):
    return render(request, 'phishAnalyzer/home.html')

def about(request):
    return render(request, 'phishAnalyzer/about.html')

def contact(request):
    return render(request, 'phishAnalyzer/contact.html')

# def scan_file(request):
#     try:
#         file = request.FILES['file']
#         files = {'file': file}
#         params = {'apikey': VIRUSTOTAL_API_KEY}
#         response = requests.post('https://www.virustotal.com/vtapi/v2/file/scan', files=files, params=params)
#         result = response.json()
        
#         if result['response_code'] == 1:
#             resource = result['resource']
#             params = {'apikey': VIRUSTOTAL_API_KEY, 'resource': resource}
#             response = requests.get('https://www.virustotal.com/vtapi/v2/file/report', params=params)
#             result = response.json()
            
#             if result['response_code'] == 1:
#                 if result['positives'] == 0:
#                     return render(request, 'phishAnalyzer/result.html', {
#                         'status': 'success',
#                         'message': 'No security vendors flagged this file as malicious:',
#                         'result': result
#                     })
#                 else:
#                     return render(request, 'phishAnalyzer/result.html', {
#                         'status': 'warning',
#                         'message': f"The file may be suspicious. Detected {result['positives']} out of {result['total']} antivirus engines.",
#                         'result': result
#                     })
#             else:
#                 return render(request, 'phishAnalyzer/result.html', {
#                     'status': 'error',
#                     'message': "Failed to retrieve file scan report."
#                 })
#         else:
#             return render(request, 'phishAnalyzer/result.html', {
#                 'status': 'error',
#                 'message': "Failed to submit the file for analysis."
#             })
#     except Exception as e:
#         return render(request, 'phishAnalyzer/result.html', {
#             'status': 'error',
#             'message': f"Error occurred while scanning the file: {e}"
#         })



def scan_file(request):
    try:
        file = request.FILES['file']
        files = {'file': file}
        params = {'apikey': VIRUSTOTAL_API_KEY}
        response = requests.post('https://www.virustotal.com/vtapi/v2/file/scan', files=files, params=params)
        result = response.json()
        
        if result['response_code'] == 1:
            resource = result['resource']
            params = {'apikey': VIRUSTOTAL_API_KEY, 'resource': resource}
            response = requests.get('https://www.virustotal.com/vtapi/v2/file/report', params=params)
            result = response.json()
            
            if result['response_code'] == 1:
                if result['positives'] == 0:
                    return render(request, 'phishAnalyzer/result.html', {
                        'status': 'success',
                        'message': 'No security vendors flagged this file as malicious:',
                        'result': result
                    })
                else:
                    return render(request, 'phishAnalyzer/result.html', {
                        'status': 'warning',
                        'message': f"The file may be suspicious. Detected {result['positives']} out of {result['total']} antivirus engines.",
                        'result': result
                    })
            else:
                return render(request, 'phishAnalyzer/result.html', {
                    'status': 'error',
                    'message': "Failed to retrieve file scan report. Error: " + result.get('verbose_msg', 'Unknown error')
                })
        else:
            return render(request, 'phishAnalyzer/result.html', {
                'status': 'error',
                'message': "Failed to submit the file for analysis."
            })
    except Exception as e:
        return render(request, 'phishAnalyzer/result.html', {
            'status': 'error',
            'message': f"Error occurred while scanning the file: {e}"
        })


def scan_url(request):
    try:
        url = request.POST.get('url')
        params = {'apikey': VIRUSTOTAL_API_KEY, 'url': url}
        
        response = requests.post('https://www.virustotal.com/vtapi/v2/url/scan', data=params)
        result = response.json()

        if result['response_code'] == 1:
            resource = result['resource']
            params = {'apikey': VIRUSTOTAL_API_KEY, 'resource': resource}
            
            response = requests.get('https://www.virustotal.com/vtapi/v2/url/report', params=params)
            result = response.json()

            if result['response_code'] == 1:
                if result['positives'] == 0:
                    return render(request, 'phishAnalyzer/result.html', {
                        'status': 'success',
                        'message': 'No security vendors flagged this URL as malicious.',
                        'result': result
                    })
                else:
                    return render(request, 'phishAnalyzer/result.html', {
                        'status': 'warning',
                        'message': f"The URL may be suspicious. Detected {result['positives']} out of {result['total']} antivirus engines.",
                        'result': result
                    })
            else:
                return render(request, 'phishAnalyzer/result.html', {
                    'status': 'error',
                    'message': 'Failed to retrieve URL scan report.'
                })
        else:
            return render(request, 'phishAnalyzer/result.html', {
                'status': 'error',
                'message': 'Failed to submit the URL for analysis.'
            })
    except Exception as e:
        return render(request, 'phishAnalyzer/result.html', {
            'status': 'error',
            'message': f'Error occurred while scanning the URL: {e}'
        })


def search(request):
    try:
        query = request.GET.get('query')
        if not query:
            return render(request, 'phishAnalyzer/result.html', {'error_message': 'Query parameter is missing.'})

        params = {'apikey': VIRUSTOTAL_API_KEY, 'resource': query}
        response = requests.get('https://www.virustotal.com/vtapi/v2/url/report', params=params)
        result = response.json()

        if result['response_code'] == 1:
            if result['positives'] == 0:
                status = 'success'
                message = 'No security vendors flagged this as malicious.'
            else:
                status = 'warning'
                message = f"The file may be suspicious. Detected {result['positives']} out of {result['total']} antivirus engines."

            return render(request, 'phishAnalyzer/result.html', {'result': result, 'status': status, 'message': message})
        else:
            return render(request, 'phishAnalyzer/result.html', {'error_message': 'Failed to retrieve scan report.'})

    except Exception as e:
        return render(request, 'phishAnalyzer/result.html', {'error_message': f"Error occurred while searching: {e}"})