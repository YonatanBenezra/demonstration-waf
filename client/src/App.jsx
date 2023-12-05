import React, { useState } from 'react';
import axios from 'axios';
import './App.css';  // Make sure to create this CSS file

function App() {
    const [requestContent, setRequestContent] = useState('');
    const [response, setResponse] = useState('');
    const [errorInfo, setErrorInfo] = useState(null);

    const handleInputChange = (event) => {
        setRequestContent(event.target.value);
    };

    const sendRequest = async () => {
        try {
            const res = await axios.post('http://localhost:3000/filter-request', { content: requestContent });
            setResponse(res.data);
            setErrorInfo(null);
        } catch (error) {
            if (error.response) {
                setErrorInfo(error.response.data);
            } else {
                setErrorInfo({ message: 'An unknown error occurred' });
            }
            setResponse('');
        }
    };

    return (
        <div className="app">
            <h1>Malicious Request Detector</h1>
            <textarea 
                className="input-area" 
                onChange={handleInputChange} 
                value={requestContent} 
                placeholder="Enter request content"
            />
            <button className="send-button" onClick={sendRequest}>Send Request</button>
            {response && <div className="response">{response}</div>}
            {console.log(errorInfo)}
            {errorInfo && (
                <div className="error-dashboard">
                    <h2>Error Detected</h2>
                    <p><strong>Message:</strong> {errorInfo.message || errorInfo}</p>
                    <p><strong>IP:</strong> {errorInfo.ip}</p>
                    <p><strong>Geolocation:</strong> {errorInfo.geoLocation}</p>
                </div>
            )}
        </div>
    );
}

export default App;
