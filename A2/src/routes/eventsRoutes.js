const express = require('express');
const router = express.Router();
const { authRequired } = require('../middleware/auth');
const eventsController = require('../controllers/eventsController');

router.post('/', authRequired, eventsController.createEvent);
router.get('/', authRequired, eventsController.listEvents);
router.get('/:eventId', authRequired, eventsController.getEvent);
router.patch('/:eventId', authRequired, eventsController.updateEvent);
router.delete('/:eventId', authRequired, eventsController.deleteEvent);

router.post('/:eventId/organizers', authRequired, eventsController.addOrganizer);
router.delete('/:eventId/organizers/:userId', authRequired, eventsController.removeOrganizer);

router.post('/:eventId/guests', authRequired, eventsController.addGuest);
router.delete('/:eventId/guests/:userId', authRequired, eventsController.removeGuest);
router.post('/:eventId/guests/me', authRequired, eventsController.addGuestSelf);
router.delete('/:eventId/guests/me', authRequired, eventsController.removeGuestSelf);

router.post('/:eventId/transactions', authRequired, eventsController.awardPoints);

module.exports = router;
