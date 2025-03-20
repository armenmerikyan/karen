def oauth_token_processor(request):
    return {"MY_TOKEN": request.session.get("MY_TOKEN", "")}
