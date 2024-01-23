import './App.css';
import React, { useState, useEffect } from "react";
import Button from 'react-bootstrap/Button';
import NavbarComponent from './NavbarComponent';


function Sniffer() {
  const [Msg, setMsg] = useState('Unknown');
  const [IP,setIP] = useState('');
  const [FlowID,setFlowID] = useState('');
  const [Label,setLabel] = useState('');
  const [anomalousFlow, setAnomalousFlow] = useState([]);
  const [categorizedFlows, setCategorizedFlows] = useState({});
  const [selectedSrcIP, setSelectedSrcIP] = useState();

  useEffect(() => {
	async function FetchAnomalousFlow() {
            const response = await fetch('https://danielmackey.ie/api/FetchAnomalousFlow/');
            const data = await response.json();
	    setAnomalousFlow(data)
	}
	FetchAnomalousFlow();
  }, []);

  useEffect(() => {
	async function fetchStatus() {
		const response = await fetch('https://danielmackey.ie/api/status/');
		const data = await response.json();
		setMsg(data.status);
	}
	fetchStatus();
  }, []);
  
  useEffect(() => {
        const categorizeFlowsBySourceIP = (flows) => {
        
            const categorized = {};
            
            flows.forEach(flow => {
            
                if (!categorized[flow.srcIP]) {
                    categorized[flow.srcIP] = [];
                }
                
                categorized[flow.srcIP].push(flow);
            });
            
            return categorized;
        };
        
        if (anomalousFlow != null) {
           const categorized = categorizeFlowsBySourceIP(anomalousFlow);
           setCategorizedFlows(categorized);
        }
    }, [anomalousFlow]);
    
    
  function getCSRFToken() {
  
     const cookieString = document.cookie;
     const csrfCookie = cookieString
       .split(';')
       .find((cookie) => cookie.trim().startsWith('csrftoken='));

   if (!csrfCookie) {
     throw new Error('CSRF token not found in cookies.');
  }

    return csrfCookie.split('=')[1];
}

  const csrftoken = getCSRFToken();
  
  const StartCaptureButton = async ()  => {
     if (Msg !== 'Sniffer On') {
	setMsg('Starting sniffer..');
	try {
		setMsg('Sniffer On');
		const response = await fetch(`https://danielmackey.ie/api/startCapture/${IP}`);
		
		if (!response.ok){
			setMsg("No connection to backend.")
		}
	} catch (error) {
		setMsg("Error turning on.")
		}
     } else {
        setMsg("Already started!")
        }
  }

  
  const ResetFlowHistory = async () => {
  	const response = await fetch(`https://danielmackey.ie/api/DeleteFlowHistory/`, {method: 'DELETE',
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
		const response = await fetch('https://danielmackey.ie/api/stopCapture/');
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
  const MoveToTraining = async () => {
  	try {
  		const JSONFlow = {
  			FlowIdentifier: FlowID,
  			ClassLabel: Label,
  		};
  		const response = await fetch(`https://danielmackey.ie/api/MoveToTraining/`, {method: 'POST',
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
   
  const showFlowByIP = (srcIP) => {
        setSelectedSrcIP(selectedSrcIP === srcIP ? null : srcIP);
    };
                     
  const alterIP = (IP) => {
        setIP(IP.target.value);
    };
  
  const BanIP = async (srcIP) => {
        try {
  		const JSONFlow = {
  			IPAddress: srcIP,
  		};
  		const response = await fetch(`https://danielmackey.ie/api/BanIP/`, {method: 'POST',
  		body: JSON.stringify(JSONFlow),
  		headers: {
        'Content-Type': 'application/json',
        'X-CSRFToken': csrftoken,
        },
  		});

  		const data = await response.json();
  		setMsg(data.status);
    
    
        if (data == null) {
  	   setMsg('No connection to backend');
  	   }
  	   
  	} catch (error) {
  		setMsg("error");
  	}
  }
  
  const UnbanIP = async (srcIP) => {
        try {
  		const JSONFlow = {
  			IPAddress: srcIP,
  		};
  		const response = await fetch(`https://danielmackey.ie/api/UnbanIP/`, {method: 'POST',
  		body: JSON.stringify(JSONFlow),
  		headers: {
        'Content-Type': 'application/json',
        'X-CSRFToken': csrftoken,
        },
  		});

  		const data = await response.json();
  		setMsg(data.status);
    
    
        if (data == null) {
  	   setMsg('No connection to backend');
  	   }
  	   
  	} catch (error) {
  		setMsg("error");
  	}
  }
  
  
    
  const alterFlowID = (flowID) => {
        setFlowID(flowID.target.value);
    };
  const alterLabel = (Label) => {
      setLabel(Label.target.value);
  };
  return (
	<>
	<NavbarComponent/>
	<h4 class="mb-3">{Msg}</h4>
	
	<div class="mb-1">
			<button onClick={StartCaptureButton}>Run Sniffer</button>
			<button onClick={StopCaptureButton}>Stop Sniffer</button>
			<button onClick={ResetFlowHistory}>Reset Flow History</button>
			</div>
	<div id="IPbox">
                <input
                    type="text"
                    value={IP}
                    onChange={alterIP}
                    placeholder="(Optional) IP to be sniffed"
                />
                </div>
        <div id="FlowIdentifier">
           <input required
              type="text"
              value={FlowID}
              onChange={alterFlowID}
              placeholder="Name the flow"
              />
        </div>
        <div id="ClassLabel">
           <input required
              type="text"
              value={Label}
              onChange={alterLabel}
              placeholder="Class name"
              />
        </div>
        <div class="mt-1">
        		<button onClick={MoveToTraining}>Move to Training</button>
        		
        		</div>
        		<h4>Anomalous Flows</h4>

        <div>
            {Object.keys(categorizedFlows).map((srcIP, index) => (
                <div key={index}>
                    <h5>Source IP: {srcIP}</h5>
                    <Button onClick={() => showFlowByIP(srcIP)}>
                    {selectedSrcIP == srcIP ? 'Hide flows' : 'Show Flows'}</Button>
                    

                    <Button onClick={() => BanIP(srcIP)}>Ban IP</Button>

                    <Button onClick={() => UnbanIP(srcIP)}>Unban IP</Button>
                    
                    {selectedSrcIP === srcIP && (
                        <ul>
                            {categorizedFlows[srcIP].map((flow, flowIndex) => (
                                <li key={flowIndex}>
                                    Flow ID: {flow.flowID} - Label: {flow.Label}
                                </li>
                            ))}
                        </ul>
                    )}
                </div>
            ))}
        </div>
        </>
        )
};
                    
export default Sniffer;
