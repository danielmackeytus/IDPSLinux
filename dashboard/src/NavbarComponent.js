import './App.css';
import React, { useState, useEffect } from "react";
import Nav from 'react-bootstrap/Nav';
import { Link, useNavigate } from 'react-router-dom';
import axios from 'axios';

axios.defaults.xsrfCookieName = 'csrftoken';
axios.defaults.xsrfHeaderName = 'X-CSRFToken';
axios.defaults.withCredentials = true;


function NavbarComponent() {

const client = axios.create({
  baseURL: "https://danielmackey.ie/"
  
});


const [TrafficStatus, setTrafficStatus] = useState('');
  
  useEffect(() => {
	
	async function fetchTrafficStatus() {
         
		const response = await fetch('https://danielmackey.ie/api/TrafficStatus/');
		
		if (response.ok) {
		const data = await response.json();
		setTrafficStatus(data.status);
		} else {
		  setTrafficStatus('network monitor not active')
		}
	}
	   fetchTrafficStatus();
	   
	   const interval = setInterval(fetchTrafficStatus, 10000);
	   
	   return () => {
              if (interval) {
                 clearInterval(interval);
             }
         };
	   
  }, []);
  
  const logout = async () => {
     try {
  	await client.post(
      		"api/logout/")
      		console.log('logged out successfully')
      		window.location.reload()
      
     } catch(error) {
     	console.log('logged out unsuccessfully')
     }
  }
  
return (
<>
<li>
  Traffic Status: <span style={{ color: TrafficStatus === 'Normal' ? 'green' : 'red' }}>{TrafficStatus}</span>
  </li>
   
  <Nav className="justify-content-center border border-dark mb-3" activeKey="/">
        <Nav.Item>
          <Nav.Link as={Link} to="/">Dashboard</Nav.Link>
        </Nav.Item>
        <Nav.Item>
          <Nav.Link as={Link} to="/sniffer">Sniffer</Nav.Link>
        </Nav.Item>
        <Nav.Item>
          <Nav.Link as={Link} to="/trainer">Trainer</Nav.Link>
        </Nav.Item>
        <Nav.Item>
          <Nav.Link onClick={logout}>Log Out</Nav.Link>
        </Nav.Item>
      </Nav>
</>
);
}
export default NavbarComponent;


