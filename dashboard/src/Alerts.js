import './App.css';
import React, { useState, useEffect } from "react";
import Button from 'react-bootstrap/Button';
import NavbarComponent from './NavbarComponent';
import Container from 'react-bootstrap/Container';
import Dropdown from 'react-bootstrap/Dropdown';

function Sniffer() {
  const [FlowID,setFlowID] = useState('');
  const [Label,setLabel] = useState('');
  const [anomalousFlow, setAnomalousFlow] = useState([]);
  const [categorizedFlows, setCategorizedFlows] = useState({});
  const [selectedSrcIP, setSelectedSrcIP] = useState();
  const [Msg, setMsg] = useState();
  const [AnomalyStatus, setAnomalyStatus] = useState('No Anomalies Detected');

  useEffect(() => {
	async function FetchAnomalousFlow() {
            const response = await fetch('https://danielmackey.ie/api/FetchAnomalousFlow/', {
            method: 'GET',
            credentials: 'include',
  		  })
            const data = await response.json();
            console.log('data',categorizedFlows.length)

	    setAnomalousFlow(data)
	    }
	
	FetchAnomalousFlow();
  }, []);
  
  useEffect(() => {
        const categorizeFlowsBySourceIP = (flows) => {
        
            const categorized = {};
            
            flows.forEach(flow => {
                if (flow.srcIP != "149.102.157.168" && flow.Label !="0") {
                    if (!categorized[flow.srcIP]) {
                   
                        categorized[flow.srcIP] = [];
                     }

                categorized[flow.srcIP].push(flow);
                }
            });
            if (categorized.length !==0) {
           setAnomalyStatus(Object.values(categorized).length + ' Anomalous Sources Detected')
        }
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


   
  const showFlowByIP = (srcIP) => {
        setSelectedSrcIP(selectedSrcIP === srcIP ? null : srcIP);
    };


  const BanIP = async (srcIP) => {
        try {

  		const JSONFlow = {
  			IPAddress: srcIP,
  		};

  		   const response = await fetch(`https://localhost:8000/api/banIP/`, { method: 'POST',
  		   credentials: 'include',
  		   body: JSON.stringify(JSONFlow),
  		   headers: {
              'Content-Type': 'application/json',
              'X-CSRFToken': csrftoken,
              },
  	    })

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

  		   const response = await fetch(`https://localhost:8000/api/unbanIP/`, { method: 'POST',
  		   credentials: 'include',
  		   body: JSON.stringify(JSONFlow),
  		   headers: {
              'Content-Type': 'application/json',
              'X-CSRFToken': csrftoken,
              },
  	    })

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
	<Container fluid>

	                <h4>{Msg}</h4>
        		<h4>{AnomalyStatus}</h4>

        <div>
            {Object.keys(categorizedFlows).map((srcIP, index) => (
                <div key={index}>
                    <h5>Source IP: {srcIP}</h5>
                 <div className="d-flex align-items-center gap-1">
                    <Button onClick={() => showFlowByIP(srcIP)}>
                    {selectedSrcIP == srcIP ? 'Hide flows' : 'Display Flows'}</Button>

                    <Dropdown>
                      <Dropdown.Toggle variant="success" id="dropdown-basic">
                        Actions
                      </Dropdown.Toggle>

                      <Dropdown.Menu>
                        <Dropdown.Item onClick={() => BanIP(srcIP)}>Ban</Dropdown.Item>
                        <Dropdown.Item onClick={() => UnbanIP(srcIP)}>Unban</Dropdown.Item>
                        <Dropdown.Item href="#/action-3">Ignore</Dropdown.Item>
                      </Dropdown.Menu>
                    </Dropdown>
                    </div>
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

        </Container>
        </>
        )
};
                    
export default Sniffer;
