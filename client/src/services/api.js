import axios from 'axios';

const API_URL = process.env.REACT_APP_API_URL || 'http://localhost:5000/api';

// Create axios instance
const api = axios.create({
  baseURL: API_URL,
  headers: {
    'Content-Type': 'application/json'
  }
});

// Add token to requests
api.interceptors.request.use(
  (config) => {
    const token = localStorage.getItem('token');
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }
    return config;
  },
  (error) => {
    return Promise.reject(error);
  }
);

// Handle auth errors
api.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response?.status === 401) {
      localStorage.removeItem('token');
      localStorage.removeItem('user');
      window.location.href = '/login';
    }
    return Promise.reject(error);
  }
);

// Auth API
export const authAPI = {
  register: (data) => api.post('/auth/register', data),
  login: (data) => api.post('/auth/login', data)
};

// Users API
export const usersAPI = {
  getAll: () => api.get('/users'),
  getById: (id) => api.get(`/users/${id}`),
  getProfile: () => api.get('/users/profile/me')
};

// Messages API
export const messagesAPI = {
  send: (data) => api.post('/messages', data),
  getConversation: (otherUserId, limit, before) => {
    const params = new URLSearchParams();
    if (limit) params.append('limit', limit);
    if (before) params.append('before', before);
    return api.get(`/messages/${otherUserId}?${params.toString()}`);
  },
  getById: (messageId) => api.get(`/messages/message/${messageId}`)
};

// Files API
export const filesAPI = {
  upload: (formData) => api.post('/files/upload', formData, {
    headers: {
      'Content-Type': 'multipart/form-data'
    }
  }),
  getMetadata: (fileId) => api.get(`/files/${fileId}`),
  download: (fileId) => api.get(`/files/${fileId}/content`, {
    responseType: 'blob'
  })
};

// Key Exchange API
export const keyExchangeAPI = {
  initiate: (data) => api.post('/key-exchange/initiate', data),
  respond: (data) => api.post('/key-exchange/respond', data),
  getPending: () => api.get('/key-exchange/pending'),
  getById: (keyExchangeId) => api.get(`/key-exchange/${keyExchangeId}`)
};

export default api;

