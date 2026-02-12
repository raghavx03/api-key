/**
 * JavaScript/Node.js Example: API Key ko kaise use karein
 */

// ============================================
// 1. SIMPLE VALIDATION (Node.js)
// ============================================

const axios = require('axios');

async function validateApiKey(apiKey) {
  try {
    const response = await axios.post('http://localhost:8000/api/validate', {
      apiKey: apiKey
    });
    
    console.log('✅ Valid API Key!');
    console.log('   User ID:', response.data.userId);
    console.log('   Key ID:', response.data.keyId);
    console.log('   Provider:', response.data.provider);
    return true;
  } catch (error) {
    console.log('❌ Invalid API Key:', error.response?.data?.detail);
    return false;
  }
}

// ============================================
// 2. EXPRESS.JS MIDDLEWARE
// ============================================

const express = require('express');
const app = express();

// API Key validation middleware
async function requireApiKey(req, res, next) {
  // API key header ya query param se le sakte ho
  const apiKey = req.headers['x-api-key'] || req.query.api_key;
  
  if (!apiKey) {
    return res.status(401).json({ error: 'API key required' });
  }
  
  try {
    const response = await axios.post('http://localhost:8000/api/validate', {
      apiKey: apiKey
    });
    
    // Valid key - add user info to request
    req.userInfo = response.data;
    next();
  } catch (error) {
    return res.status(401).json({ error: 'Invalid API key' });
  }
}

// Protected route
app.get('/api/protected', requireApiKey, (req, res) => {
  res.json({
    message: 'Success! You have access',
    user: req.userInfo
  });
});

// ============================================
// 3. FETCH API (Browser/Node.js)
// ============================================

async function callApiWithKey(apiKey) {
  // Method 1: Header mein
  const response1 = await fetch('http://your-api.com/data', {
    headers: {
      'X-API-Key': apiKey
    }
  });
  
  // Method 2: Query parameter
  const response2 = await fetch(`http://your-api.com/data?api_key=${apiKey}`);
  
  // Method 3: Body mein (POST request)
  const response3 = await fetch('http://localhost:8000/api/validate', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({ apiKey: apiKey })
  });
  
  return await response3.json();
}

// ============================================
// 4. AXIOS WITH INTERCEPTORS
// ============================================

// Create axios instance with API key
const apiClient = axios.create({
  baseURL: 'http://your-api.com'
});

// Add API key to all requests
apiClient.interceptors.request.use(config => {
  const apiKey = 'akm_your_key_here'; // Ya environment variable se lo
  config.headers['X-API-Key'] = apiKey;
  return config;
});

// Use it
async function getData() {
  const response = await apiClient.get('/data');
  return response.data;
}

// ============================================
// 5. REACT EXAMPLE
// ============================================

import React, { useState, useEffect } from 'react';

function ApiKeyProtectedComponent() {
  const [data, setData] = useState(null);
  const [error, setError] = useState(null);
  
  useEffect(() => {
    async function fetchData() {
      const apiKey = localStorage.getItem('apiKey'); // Dashboard se save kiya hua
      
      if (!apiKey) {
        setError('No API key found');
        return;
      }
      
      try {
        // First validate
        const validateResponse = await fetch('http://localhost:8000/api/validate', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ apiKey })
        });
        
        if (!validateResponse.ok) {
          throw new Error('Invalid API key');
        }
        
        // Then fetch data
        const dataResponse = await fetch('http://your-api.com/data', {
          headers: { 'X-API-Key': apiKey }
        });
        
        const result = await dataResponse.json();
        setData(result);
      } catch (err) {
        setError(err.message);
      }
    }
    
    fetchData();
  }, []);
  
  if (error) return <div>Error: {error}</div>;
  if (!data) return <div>Loading...</div>;
  
  return <div>Data: {JSON.stringify(data)}</div>;
}

// ============================================
// 6. OPENAI WITH YOUR API KEY
// ============================================

const OpenAI = require('openai');

async function useOpenAIWithValidation(yourApiKey, openaiApiKey) {
  // Step 1: Validate your API key
  const isValid = await validateApiKey(yourApiKey);
  
  if (!isValid) {
    console.log('Access denied!');
    return;
  }
  
  // Step 2: Use OpenAI
  const openai = new OpenAI({ apiKey: openaiApiKey });
  
  const completion = await openai.chat.completions.create({
    model: "gpt-4",
    messages: [
      { role: "user", content: "Hello!" }
    ]
  });
  
  console.log(completion.choices[0].message.content);
}

// ============================================
// 7. RATE LIMITING
// ============================================

class RateLimiter {
  constructor() {
    this.requests = new Map();
    this.limits = {
      free: 10,      // 10 requests per minute
      premium: 100   // 100 requests per minute
    };
  }
  
  async checkRateLimit(apiKey) {
    // Validate key first
    try {
      const response = await axios.post('http://localhost:8000/api/validate', {
        apiKey: apiKey
      });
      
      const userId = response.data.userId;
      const now = Date.now();
      const minuteAgo = now - 60000;
      
      // Get user's requests
      if (!this.requests.has(userId)) {
        this.requests.set(userId, []);
      }
      
      const userRequests = this.requests.get(userId);
      
      // Remove old requests
      const recentRequests = userRequests.filter(time => time > minuteAgo);
      
      // Check limit
      const tier = response.data.tier || 'free';
      if (recentRequests.length >= this.limits[tier]) {
        return { allowed: false, message: `Rate limit exceeded: ${this.limits[tier]}/min` };
      }
      
      // Add current request
      recentRequests.push(now);
      this.requests.set(userId, recentRequests);
      
      return { allowed: true, message: 'OK' };
    } catch (error) {
      return { allowed: false, message: 'Invalid API key' };
    }
  }
}

// ============================================
// 8. CACHING FOR PERFORMANCE
// ============================================

class CachedValidator {
  constructor(cacheTTL = 300000) { // 5 minutes
    this.cache = new Map();
    this.cacheTTL = cacheTTL;
  }
  
  async validate(apiKey) {
    const now = Date.now();
    
    // Check cache
    if (this.cache.has(apiKey)) {
      const { time, result } = this.cache.get(apiKey);
      if (now - time < this.cacheTTL) {
        console.log('✅ Using cached validation');
        return result;
      }
    }
    
    // Validate
    try {
      await axios.post('http://localhost:8000/api/validate', {
        apiKey: apiKey
      });
      
      // Cache result
      this.cache.set(apiKey, { time: now, result: true });
      return true;
    } catch (error) {
      this.cache.set(apiKey, { time: now, result: false });
      return false;
    }
  }
}

// ============================================
// 9. USAGE EXAMPLES
// ============================================

async function main() {
  const apiKey = 'akm_your_key_here'; // Dashboard se copy karo
  
  // Example 1: Simple validation
  console.log('\n=== Example 1: Simple Validation ===');
  await validateApiKey(apiKey);
  
  // Example 2: With axios
  console.log('\n=== Example 2: Axios Request ===');
  try {
    const response = await axios.get('http://your-api.com/data', {
      headers: { 'X-API-Key': apiKey }
    });
    console.log(response.data);
  } catch (error) {
    console.log('Error:', error.message);
  }
  
  // Example 3: Rate limiting
  console.log('\n=== Example 3: Rate Limiting ===');
  const limiter = new RateLimiter();
  const result = await limiter.checkRateLimit(apiKey);
  console.log('Allowed:', result.allowed, 'Message:', result.message);
  
  // Example 4: Cached validation
  console.log('\n=== Example 4: Cached Validation ===');
  const validator = new CachedValidator();
  const isValid = await validator.validate(apiKey);
  console.log('Valid:', isValid);
}

// Run examples
// main();

// ============================================
// 10. ENVIRONMENT VARIABLES
// ============================================

// .env file mein save karo:
// API_KEY=akm_your_key_here

// Use karo:
require('dotenv').config();
const myApiKey = process.env.API_KEY;

module.exports = {
  validateApiKey,
  requireApiKey,
  callApiWithKey,
  RateLimiter,
  CachedValidator
};
