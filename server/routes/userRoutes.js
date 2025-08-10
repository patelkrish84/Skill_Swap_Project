import express from 'express'
import userAuth from '../middleware/userAuth.js';
import { getUserData } from '../controllers/userController.js';


const userRoutesr = express.Router();

userRoutesr.get('/data', userAuth, getUserData);

export default userRoutesr;