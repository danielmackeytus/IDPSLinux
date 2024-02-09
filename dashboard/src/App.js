import './App.css';
import React, { useState, useEffect } from "react";
import { BrowserRouter as Router, Route, Routes } from 'react-router-dom';

import 'bootstrap/dist/css/bootstrap.min.css';

import Navbar from 'react-bootstrap/Navbar';
import Button from 'react-bootstrap/Button';
import Form from 'react-bootstrap/Form';

import Sniffer from './Sniffer';
import Dashboard from './Dashboard';
import Trainer from './Trainer';
import Alerts from './Alerts';

import axios from 'axios';
import Container from 'react-bootstrap/Container';

axios.defaults.xsrfCookieName = 'csrftoken';
axios.defaults.xsrfHeaderName = 'X-CSRFToken';
axios.defaults.withCredentials = true;

const client = axios.create({
  baseURL: "https://danielmackey.ie/",
  withCredentials: true,
});

function App() {
  
  const [currentUser, setCurrentUser] = useState();
  const [currentUserGroup, setCurrentUserGroup] = useState([]);
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  
  useEffect(() => {
  
     try {
    	client.get("api/user/")
    	.then(function(res) {
      	setCurrentUser(true);
      	setCurrentUserGroup(res.data.user.groups)
    	}
      )
    	} catch(AttributeError) {
		
      		setCurrentUser(false);
      		
    	}
  	}, []);
  
  
  const NoAccessComponent = ({ group }) => (
    <div>
      <h2>You are not a {group}</h2>
      <p>You do not have permission to view this page.</p>
    </div>
  );
  
  
  function submitLogin(e) {
    e.preventDefault();
    client.post(
      "api/login/",
      {
        email: email,
        password: password
      }
    ).then(() => {
      return client.get(
      "api/user/");
      })
      .then(res => {
      	setCurrentUser(true);
        setCurrentUserGroup(res.data.user.groups);
})
}
  
  if (currentUserGroup.includes(1) && currentUserGroup.includes(2)) {	
  return (
		<Router>
			<Routes>
				<Route path="/" element={<Dashboard />} />
				<Route path="/trainer" element={<Trainer />} />
				<Route path="/sniffer" element={<Sniffer />} />
				<Route path="/alerts" element={<Alerts />} />
			</Routes>
		</Router>

		);
	}
	
  else if (currentUserGroup.includes(1)) {	
  return (
		<Router>
			<Routes>
				<Route path="/" element={<Dashboard />} />
				<Route path="/sniffer" element={<Sniffer />} />
				<Route path="/alerts" element={<Alerts />} />
				<Route path="/trainer" element={<NoAccessComponent group="Data Flow Architect" />} />
			</Routes>
		</Router>

		);
	}
  else if (currentUserGroup.includes(2)) {	
  return (
		<Router>
			<Routes>
				<Route path="/" element={<Dashboard />} />
				<Route path="/trainer" element={<Trainer />} />
				<Route path="/sniffer" element={<NoAccessComponent group="Machine Learning Engineer" />} />
			</Routes>
		</Router>

		);
	}
	
  else {

  return (
    <div>
    <Navbar bg="dark" variant="dark">
      <Container>
        <Navbar.Brand>Authentication</Navbar.Brand>
      </Container>
    </Navbar>
    {
        (
        <div className="center">
          <Form onSubmit={e => submitLogin(e)}>
            <Form.Group className="mb-3" controlId="formBasicEmail">
              <Form.Label>Email address</Form.Label>
              <Form.Control type="email" placeholder="Enter email" value={email} onChange={e => setEmail(e.target.value)} />

            </Form.Group>
            <Form.Group className="mb-3" controlId="formBasicPassword">
              <Form.Label>Password</Form.Label>
              <Form.Control type="password" placeholder="Password" value={password} onChange={e => setPassword(e.target.value)} />
            </Form.Group>
            <Button variant="primary" type="submit">
              Submit
            </Button>
          </Form>
        </div>
      )
    }
    </div>
  );
}
	}

export default App;
