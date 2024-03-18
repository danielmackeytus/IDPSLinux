import './App.css';
import React, { useState, useEffect } from "react";
import Nav from 'react-bootstrap/Nav';
import { Link, useNavigate } from 'react-router-dom';
import axios from 'axios';
import Container from 'react-bootstrap/Container';

axios.defaults.xsrfCookieName = 'csrftoken';
axios.defaults.xsrfHeaderName = 'X-CSRFToken';


function NavbarComponent() {

const client = axios.create({
  baseURL: "https://danielmackey.ie/",
  withXSRFToken: true,
});


const [TrafficStatus, setTrafficStatus] = useState('');

  useEffect(() => {

	async function fetchTrafficStatus() {
         
		const response = await fetch('https://danielmackey.ie/api/TrafficStatus/', {
           method: 'GET',
		   credentials: 'include',
		   }
		);
		
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
      		"api/logout/");

      		console.log('logged out successfully')
      		window.location.href = ('https://danielmackey.ie')
      
     } catch(error) {
     	console.log('logged out unsuccessfully')
     }
  }

return (
<>
  <Container fluid>
  <li>
  Traffic Status: <span style={{ color: TrafficStatus === 'Normal' ? 'green' : 'red' }}>{TrafficStatus}</span>
  </li>
  </Container>

  <Nav className="shadow bg-body justify-content-center border border-dark mb-3" activeKey="/">
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
          <Nav.Link as={Link} to="/alerts">Alerts</Nav.Link>
          </Nav.Item>
        <Nav.Item>
          <Nav.Link onClick={logout}>Log Out</Nav.Link>
        </Nav.Item>
      </Nav>
</>
);
}
export default NavbarComponent;


