import requests
import time

# Nextcloud API endpoint for fetching activity
api_endpoint = 'http://localhost:8080/ocs/v2.php/apps/activity/api/v2/activity'

# Parameters for API request
params = {
    'format': 'json',
    'filter': 'create',
    'object_type': 'files',
    'limit': 10,  # Number of recent activities to fetch
    'sort': 'desc',
}

# Store the IDs of previously fetched activities
previous_activity_ids = set()

while True:
    try:
        # Make the API request to fetch recent activity
        response = requests.get(api_endpoint, params=params)

        # Check the response status code
        if response.status_code == 200:
            activity_data = response.json()

            # Extract the activity entries from the response
            activity_entries = activity_data['ocs']['data']

            # Iterate over the activity entries
            for entry in activity_entries:
                activity_id = entry['id']
                if activity_id not in previous_activity_ids:
                    # New file creation activity detected
                    user = entry['user']
                    timestamp = entry['timestamp']
                    file_path = entry['subject']['file']

                    # Perform desired actions with the new file creation
                    print(f'New file created by {user} at {timestamp}: {file_path}')

                    # Add the activity ID to the set of previous activity IDs
                    previous_activity_ids.add(activity_id)

        else:
            # Request failed
            print(f'Failed to fetch activity. Status Code: {response.status_code}')

    except Exception as e:
        # Handle any exceptions that occur during the API request
        print(f'Error occurred: {str(e)}')

    # Wait for a specified interval before the next API request
    time.sleep(60)  # Delay for 60 seconds before the next check
