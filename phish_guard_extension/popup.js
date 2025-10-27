// popup.js - Browser Extension JavaScript
// This script handles the functionality of the Phish-Guard browser extension popup
// It manages URL scanning requests and displays results to the user

// Ensure the code runs only after the HTML page is fully loaded
document.addEventListener('DOMContentLoaded', function() {

    // 1. Find the HTML elements we'll be working with
    const checkButton = document.getElementById('checkButton');
    const resultDiv = document.getElementById('result');

    // 2. Add event listener for the check button click
    // This means: "when the button is clicked, execute this function"
    checkButton.addEventListener('click', function() {
        
        // Display "Checking..." message immediately to inform the user
        resultDiv.textContent = 'Checking...';
        resultDiv.style.color = 'orange';

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
                // 5. Display the final result returned from Django
                displayResult(data.result);
            })
            .catch(error => {
                // 6. Handle any errors (e.g., Django server not running)
                console.error('Error:', error);
                displayResult('Error: Could not connect to server.');
            });
        });
    });

    // Helper function to change the color and appearance of the result
    function displayResult(resultText) {
        resultDiv.textContent = resultText;
        if (resultText.toLowerCase() === 'phishing') {
            resultDiv.style.color = 'red';
        } else if (resultText.toLowerCase() === 'legitimate') {
            resultDiv.style.color = 'green';
        } else {
            resultDiv.style.color = 'black'; // For other messages like errors
        }
    }
});