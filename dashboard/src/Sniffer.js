import './App.css';
import React, { useState, useEffect } from "react";
import Button from 'react-bootstrap/Button';
import NavbarComponent from './NavbarComponent';
import Container from 'react-bootstrap/Container';
import Card from 'react-bootstrap/Card';
import abuseIpdbLogo from './abuseipdb-logo.jpg';
import WrenchLogo from './wrench.png';

function Sniffer() {
  const [Msg, setMsg] = useState('Unknown');
  const [IP,setIP] = useState('');
  const [FlowID,setFlowID] = useState('');
  const [Label,setLabel] = useState('');

  useEffect(() => {
	async function fetchStatus() {
		const response = await fetch('https://danielmackey.ie/api/status/', {
		method: 'GET',
		credentials: 'include',
		})
		const data = await response.json();
		setMsg(data.status);

	}
	fetchStatus();
  }, []);
  
    
  function getCSRFToken() {
  
     const cookieString = document.cookie;
     const csrfCookie = cookieString
       .split(';')
       .find((cookie) => cookie.trim().startsWith('csrftoken='));

   if (!csrfCookie) {
     return 0
  }

    return csrfCookie.split('=')[1];
}

  const csrftoken = getCSRFToken();
  
  const StartCaptureButton = async ()  => {
     if (Msg !== 'Sniffer On') {
	    setMsg('Starting sniffer..');
	try {
		setMsg('Sniffer On');
		const response = await fetch(`https://danielmackey.ie/api/startCapture/${IP}/`, {
		method: 'POST',
		credentials: 'include',
  	    headers: {
  	    'Content-Type': 'application/json',
  	    'X-CSRFToken': csrftoken,
  	    }

  	    });

		if (!response.ok){
			setMsg("No connection to backend.")
		}
		
		const data = await response.json();
		setMsg(data.status)
        
	} catch (error) {
		setMsg("Error turning on.")
		}
     } else {
        setMsg("Already started!")
        }
        
  }

  const ResetFlowHistory = async () => {
  	const response = await fetch(`https://danielmackey.ie/api/DeleteFlowHistory/`, {method: 'DELETE',
  	credentials: 'include',

  	headers: {
  	'Content-Type': 'application/json',
  	'X-CSRFToken': csrftoken,
  	}})

  	const data = await response.json();
  	setMsg(data.message);
  	
  	if (data == null) {
  	   setMsg('No connection to backend');
  	   }
  
}

  const StopCaptureButton = async () => {
	setMsg('Stopping sniffer..');
	try {
		const response = await fetch('https://danielmackey.ie/api/stopCapture/', {
		method: 'POST',
		credentials: 'include',
		headers: {
  	      'Content-Type': 'application/json',
  	      'X-CSRFToken': csrftoken,
		}});

		if (response.ok) {
			const data = await response.json();
			setMsg(data.status);
			
		} else {
			setMsg("No connection to backend.")
		}
	} catch (error) {
		setMsg("Sniffer not turned off.");
		}
  }

  const AbuseIPDB = async ()  => {
	try {
	    setMsg('AbuseIPDBing..');
		const response = await fetch(`https://danielmackey.ie/api/AbuseIPDB/`, {
		method: 'GET',
		credentials: 'include',
  	    });

		if (!response.ok){
			setMsg("No connection to backend.")
		}
    } catch(error) {
        console.log('what')
    }
    }

  const MoveToTraining = async () => {
  	try {
  		const JSONFlow = {
  			ClassLabel: Label,
  		};
  		const response = await fetch(`https://danielmackey.ie/api/MoveToTraining/`, {
  		method: 'POST',
  		credentials: 'include',
  		body: JSON.stringify(JSONFlow),
  		headers: {
           'Content-Type': 'application/json',
           'X-CSRFToken': csrftoken,
           },
  		});

  		const data = await response.json();
  		setMsg(data.message);
  	
  	if (data == null) {
  	   setMsg('No connection to backend');
  	   }
  	} catch (error) {
  		setMsg("error");
  	}
  }
    
  const alterIP = (IP) => {
        setIP(IP.target.value);
    };
  
    
  const alterFlowID = (flowID) => {
        setFlowID(flowID.target.value);
    };
  const alterLabel = (Label) => {
      setLabel(Label.target.value);
  };
  return (
	<>

	<NavbarComponent/>
<Container fluid>

	<h4 class="mb-3">{Msg}</h4>
	<div class="mb-2 d-flex gap-1">

			<button onClick={StartCaptureButton}
			className="btn btn-primary">Run Sniffer</button>

			<button onClick={StopCaptureButton}
			className="btn btn-danger">Stop Sniffer</button>

			<button onClick={ResetFlowHistory}
			className="btn btn-light">Reset Flow History</button>
			</div>

        <div class="mt-1 IPbox">
                    <input
                        type="text"
                        value={IP}
                        onChange={alterIP}
                        placeholder="(Optional) IP to be sniffed"
                    />
                    </div>



        <div className="mt-5 text-center">
            <h5 className="mb-4">Post Sniffing</h5>
            <Card><div>
                <img src={abuseIpdbLogo}
                 style={{ width: '125px', height: '125px' }}
                 className="mt-2 card-img-top" alt="AbuseIPDB Logo" />

                <Card.Body className="mt-2 mb-2">
                    <p class="card-text">This button gets the first 25 reports within the past 2 weeks from <u><i>AbuseIPDB.com</i></u> based on each flow source IP.</p>
                    <p class="card-text">It then calculates the average category assigned by global users.</p>
                    <p class="card-text">This intelligence assigns each flow said category.</p>
                    <p class="card-text">Can be used to split normal and abnormal.</p>
                    <Button onClick={AbuseIPDB} variant="success">Categorize using AbuseIPDB</Button>
                </Card.Body>
                    </div>
             </Card>

            <Card className="mt-5 mb-5">
            <Card.Body className="mt-2 mb-2">
            <div>
                <img src={WrenchLogo}
                 style={{ width: '125px', height: '125px' }}
                 className="mt-2 card-img-top" alt="Wrench Logo" />

                <p class="card-text">This button can be used if you are orchestrating your own attacks on the IDPS.</p>
                <p class="card-text">Requires you enter your own flow name below.</p>
               <div class="mb-1 Label">
                    <input required
                          type="text"
                          value={Label}
                          onChange={alterLabel}
                          placeholder="Class name"
                     />
                </div>
                    <button onClick={MoveToTraining}
                    className="btn btn-light">Custom Categorization</button>
            </div>


        </Card.Body>
        </Card></div>
        </Container>
        </>
        )
};
                    
export default Sniffer;
