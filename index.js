
const express = require('express');
const mongoose = require('mongoose');
const dotenv = require('dotenv');
const bcrypt = require('bcryptjs');  
const jwt = require('jsonwebtoken'); 
const cors = require('cors');
const bodyParser = require('body-parser');
const { questionsData, correctOptionIds } = require('./questionsData');



dotenv.config();                                                       // Load environment variables 
const app = express();                                                  
app.use(cors());

const mongoURI = process.env.MONGO_URI;
const jwtSecret = process.env.JWT_SECRET;

const connectDB = async () => {                                        // Connect to MongoDB
    try {
      await mongoose.connect(mongoURI, {
        useNewUrlParser: true,
        useUnifiedTopology: true
      });
      console.log('MongoDB Connected');
    } catch (err) {
      console.error('Error connecting to MongoDB:', err);
      process.exit(1);
    }
  };

  
const userSchema = new mongoose.Schema({                               // Define user schema
    username: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    score: { type: Number, default: 0 } 
  });
const User = mongoose.model('User', userSchema);                        // Create model from schema




app.use(express.json());                                               // Middleware to parse JSON request bodies 
connectDB();                                                           // Connect to database



app.use(bodyParser.json());

app.post('/signup', async (req, res) => {
    const { username, password } = req.body;
   
    
    try {
      
      const existingUser = await User.findOne({ username });                                    // Check if the user already exists
      if (existingUser) {
        return res.status(400).json({ error: 'Username already exists. Please choose a different username.' });
      }
  
                                                                                                
      const salt = await bcrypt.genSalt(10);                                                    // Hash the password before saving
      const hashedPassword = await bcrypt.hash(password, salt);
  
      
      const newUser = new User({                                                                // Create a new User document and save it to the database
        username,
        password: hashedPassword                                                                // Save the hashed password
      });
      await newUser.save();
  
      res.status(201).json({ message: 'User created successfully', user: { username: newUser.username, score: newUser.score } });
    } catch (error) {
      res.status(500).json({ error: 'Error creating user' });
    }
  });



  app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    try {
      
      const user = await User.findOne({ username });                                                                        // Check if the user exists
      if (!user) {
        return res.status(400).json({ error: 'Username does not exist. Please signup.' });
      }
      const isMatch = await bcrypt.compare(password, user.password);                                                        // Compare the entered password with the hashed password
      if (!isMatch) {
        return res.status(400).json({ error: 'Password mismatch. Please enter the correct password.' });
      }

      const token = jwt.sign(
        { userId: user._id, username: user.username }, // Payload (data to be encoded)
        process.env.JWT_SECRET, // Secret key
        { expiresIn: '1h' } // Token expiration time (optional)
      );
  
      
      res.status(200).json({ message: 'Login successful', token });   // Send the JWT token in the response
    } catch (error) {
      res.status(500).json({ error: 'Error logging in user' });
    }
  });

  app.get('/correct',(req,res)=>{
    res.json(correctOptionIds);

  });


  app.get('/assess/questions', (req, res) => {
    
    res.json(questionsData);
  });

  app.post('/updatescore', async (req, res) => {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) {
        return res.status(401).json({ error: 'Authorization token required' });
    }

    try {
        const decoded = jwt.verify(token, jwtSecret);
        const username = decoded.username;

        const { marksSheet } = req.body;
        let score = 0;

        marksSheet.forEach((item, index) => {                       // Update the score based on the logic provided
            if (item.status === 'a' && item.oid === correctOptionIds[index]) {
                score += 1;
            }
        });

        const user = await User.findOne({ username });
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }

        user.score = score;
        await user.save();

        res.json({ score });    // Send the score back in the response
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Internal server error' });
    }
});
  

const PORT = process.env.PORT || 3000;                                                          //start the server
app.listen(PORT, () => console.log(`Server is running on port ${PORT}`));



