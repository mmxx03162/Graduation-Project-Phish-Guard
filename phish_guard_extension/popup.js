// popup.js - Browser Extension JavaScript
// This script handles the functionality of the Phish-Guard browser extension popup
// It manages URL scanning requests and displays results to the user

// Ensure the code runs only after the HTML page is fully loaded
document.addEventListener('DOMContentLoaded', function() {

    // 1. Find the HTML elements we'll be working with
    const checkButton = document.getElementById('checkButton');
    const resultContainer = document.getElementById('result-container');
    const resultTitle = document.getElementById('result-title');
    const resultReason = document.getElementById('result-reason');

    // 2. Add event listener for the check button click
    // This means: "when the button is clicked, execute this function"
    checkButton.addEventListener('click', function() {
        
        // Hide previous results and show checking message
        resultContainer.style.display = 'block';
        resultTitle.textContent = 'Checking...';
        resultTitle.style.color = 'orange';
        resultReason.textContent = 'Please wait while we analyze the site...';

        // 3. Request the current page URL from Chrome
        chrome.tabs.query({active: true, currentWindow: true}, function(tabs) {
            const currentUrl = tabs[0].url;

            // 4. Send the URL to our Django API
            fetch('http://127.0.0.1:8000/api/scan/', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                // Convert our data to JSON format
                body: JSON.stringify({ url: currentUrl }),
            })
            .then(response => {
                // Ensure the server response is valid
                if (!response.ok) {
                    throw new Error('Network response was not ok');
                }
                return response.json(); // Convert response to JSON
            })
            .then(data => {
                // 5. Display the final result and reason returned from Django
                displayResult(data.result, data.reason);
            })
            .catch(error => {
                // 6. Handle any errors (e.g., Django server not running)
                console.error('Error:', error);
                displayResult('Error', 'Could not connect to server. Please make sure the backend is running.');
            });
        });
    });

    // Helper function to change the color and appearance of the result
    function displayResult(resultText, reasonText) {
        // Show the result container
        resultContainer.style.display = 'block';
        
        // Display the result title
        resultTitle.textContent = resultText;
        
        // Set colors based on result
        if (resultText.toLowerCase() === 'phishing') {
            resultTitle.style.color = 'red';
            resultContainer.style.backgroundColor = '#ffe6e6';
            resultContainer.style.border = '2px solid #ff4444';
        } else if (resultText.toLowerCase() === 'legitimate') {
            resultTitle.style.color = 'green';
            resultContainer.style.backgroundColor = '#e6ffe6';
            resultContainer.style.border = '2px solid #44ff44';
        } else {
            resultTitle.style.color = 'black';
            resultContainer.style.backgroundColor = '#f0f0f0';
            resultContainer.style.border = '2px solid #888';
        }
        
        // Display the reason
        resultReason.textContent = reasonText || 'No additional information available.';
    }
});