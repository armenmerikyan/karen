import requests

# Base API URL for Support Ticket service
SUPPORT_TICKET_API_BASE_URL = "https://gigahard.ai/api/support-tickets"

def fetch_all_businesses():
    """Fetches all businesses from the MCP API."""
    try:
        api_url = "https://gigahard.ai/api/businesses/"
        response = requests.get(api_url)
        print(f"Fetching All Businesses: {api_url}, Status: {response.status_code}")
        if response.status_code == 200:
            return response.json()
        return {"error": f"MCP API returned {response.status_code}", "response": response.text}
    except Exception as e:
        print(f"Error fetching businesses: {str(e)}")
        return {"error": str(e)}


def fetch_mcp_data(business_id):
    """Fetches MCP API data for business context based on ID."""
    try:
        api_url = f"https://gigahard.ai/api/businesses/{business_id}/"
        response = requests.get(api_url)
        print(f"Fetching MCP Data: {api_url}, Status: {response.status_code}")
        if response.status_code == 200:
            return response.json()
        return {"error": f"MCP API returned {response.status_code}", "response": response.text}
    except Exception as e:
        print(f"Error fetching MCP data: {str(e)}")
        return {"error": str(e)}

def create_business(business_data):
    """Creates a new business entry in Gigahard MCP."""
    try:
        api_url = "https://gigahard.ai/api/businesses/create/"
        response = requests.post(api_url, json=business_data)
        print(f"Creating Business: {business_data}, Status: {response.status_code}")
        if response.status_code == 201:
            return response.json()
        return {"error": f"Business creation failed {response.status_code}", "response": response.text}
    except Exception as e:
        print(f"Error creating business: {str(e)}")
        return {"error": str(e)}
    

def create_support_ticket(ticket_data):
    """Creates a new support ticket in Gigahard MCP."""
    try:
        api_url = f"{SUPPORT_TICKET_API_BASE_URL}/create/"
        response = requests.post(api_url, json=ticket_data)
        print(f"Creating Support Ticket: {ticket_data}, Status: {response.status_code}")
        if response.status_code == 201:
            return response.json()
        return {"error": f"Support ticket creation failed {response.status_code}", "response": response.text}
    except Exception as e:
        print(f"Error creating support ticket: {str(e)}")
        return {"error": str(e)}

def fetch_support_ticket(ticket_id):
    """Retrieves support ticket details by ID from Gigahard MCP."""
    try:
        api_url = f"{SUPPORT_TICKET_API_BASE_URL}/{ticket_id}/"
        response = requests.get(api_url)
        print(f"Fetching Support Ticket ID {ticket_id}, Status: {response.status_code}")
        if response.status_code == 200:
            return response.json()
        return {"error": f"Support ticket fetch failed {response.status_code}", "response": response.text}
    except Exception as e:
        print(f"Error fetching support ticket: {str(e)}")
        return {"error": str(e)}

def fetch_all_support_tickets():
    """Retrieves a list of all support tickets from Gigahard MCP."""
    try:
        api_url = f"{SUPPORT_TICKET_API_BASE_URL}/"
        response = requests.get(api_url)
        print(f"Fetching All Support Tickets, Status: {response.status_code}")
        if response.status_code == 200:
            return response.json()
        return {"error": f"Support ticket list fetch failed {response.status_code}", "response": response.text}
    except Exception as e:
        print(f"Error fetching all support tickets: {str(e)}")
        return {"error": str(e)}
