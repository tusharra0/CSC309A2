const eventsService = require('../services/eventsService');

const handle = async (res, action, successStatus = 200) => {
  try {
    const payload = await action();
    if (successStatus === 204) {
      return res.status(204).send();
    }
    return res.status(successStatus).json(payload);
  } catch (err) {
    if (err.status) {
      return res.status(err.status).json({ message: err.message });
    }
    console.error(err);
    return res.status(500).json({ message: 'Unexpected server error' });
  }
};

exports.createEvent = (req, res) =>
  handle(res, () => eventsService.createEvent({ body: req.body || {}, user: req.user }), 201);

exports.listEvents = (req, res) =>
  handle(res, () => eventsService.listEvents({ user: req.user, query: req.query }), 200);


exports.getEvent = (req, res) => {
  const eventId = Number(req.params.eventId);
  if (!Number.isInteger(eventId)) {
    return res.status(400).json({ message: 'Invalid event id' });
  }

  return handle(
    res,
    () => eventsService.fetchEventForView({ eventId, user: req.user }),
    200
  );
};

exports.updateEvent = (req, res) => {
  const eventId = Number(req.params.eventId);
  if (!Number.isInteger(eventId)) {
    return res.status(400).json({ message: 'Invalid event id' });
  }
  return handle(res, () =>
    eventsService.updateEvent({
      eventId,
      user: req.user,
      body: req.body || {}
    })
  );
};

exports.deleteEvent = (req, res) => {
  const eventId = Number(req.params.eventId);
  if (!Number.isInteger(eventId)) {
    return res.status(400).json({ message: 'Invalid event id' });
  }
  return handle(res, () => eventsService.deleteEvent({ eventId, user: req.user }), 204);
};

exports.addOrganizer = (req, res) => {
  const eventId = Number(req.params.eventId);
  if (!Number.isInteger(eventId)) {
    return res.status(400).json({ message: 'Invalid event id' });
  }
  return handle(
    res,
    () =>
      eventsService.addOrganizer({
        eventId,
        utorid: req.body?.utorid,
        user: req.user
      }),
    201 
  );
};

exports.removeOrganizer = (req, res) => {
  const eventId = Number(req.params.eventId);
  const userId = Number(req.params.userId);

  if (!Number.isInteger(eventId) || !Number.isInteger(userId)) {
    return res.status(400).json({ message: 'Invalid id' });
  }

  return handle(
    res,
    () =>
      eventsService.removeOrganizer({
        eventId,
        organizerUserId: userId,
        user: req.user
      }),
    200
  );
};

exports.addGuest = (req, res) => {
  const eventId = Number(req.params.eventId);
  if (!Number.isInteger(eventId)) {
    return res.status(400).json({ message: 'Invalid event id' });
  }
  return handle(
    res,
    () =>
      eventsService.addGuest({
        eventId,
        utorid: req.body?.utorid,
        user: req.user
      }),
    200
  );
};

exports.addGuestSelf = (req, res) => {
  const eventId = Number(req.params.eventId);
  if (!Number.isInteger(eventId)) {
    return res.status(400).json({ message: 'Invalid event id' });
  }
  return handle(
    res,
    () =>
      eventsService.addGuestSelf({
        eventId,
        user: req.user
      }),
    201
  );
};

exports.removeGuest = (req, res) => {
  const eventId = Number(req.params.eventId);
  const userId = Number(req.params.userId);
  if (!Number.isInteger(eventId) || !Number.isInteger(userId)) {
    return res.status(400).json({ message: 'Invalid event id' });
  }
  return handle(
    res,
    () =>
      eventsService.removeGuest({
        eventId,
        userId,
        user: req.user
      }),
    204
  );
};

exports.removeGuestSelf = (req, res) => {
  const eventId = Number(req.params.eventId);
  if (!Number.isInteger(eventId)) {
    return res.status(400).json({ message: 'Invalid event id' });
  }
  return handle(
    res,
    () =>
      eventsService.removeGuestSelf({
        eventId,
        user: req.user
      }),
    204
  );
};

exports.awardPoints = (req, res) => {
  const eventId = Number(req.params.eventId);
  if (!Number.isInteger(eventId)) {
    return res.status(400).json({ message: 'Invalid event id' });
  }
  return handle(
    res,
    () =>
      eventsService.awardEventPoints({
        eventId,
        user: req.user,
        body: req.body || {}
      }),
    201
  );
};
