from app import create_app
import os

app = create_app()

if __name__ == '__main__':
    # Bind to 0.0.0.0 to be accessible in a container.
    # Use the PORT environment variable provided by Render, defaulting to 5000 for local dev.
    port = int(os.getenv('PORT', 5000))
    app.run(debug=False, host='0.0.0.0', port=port)
