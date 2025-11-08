const { PrismaClient } = require('@prisma/client');

const prisma = new PrismaClient();

const createError = (status, message) => {
  const error = new Error(message);
  error.status = status;
  return error;
};

const hasRole = (user, ...roles) => {
  const role = typeof user?.role === 'string' ? user.role.toLowerCase() : undefined;
  if (!role) return false;
  const allowed = roles.flat();
  return allowed.includes(role);
};

const organizerInclude = {
  organizers: {
    include: {
      user: true
    }
  },
  guests: true
};

const mapPerson = (user) => ({
  id: user.id,
  utorid: user.utorid,
  name: user.name
});

const mapOrganizers = (event) =>
  (event.organizers || []).map((link) => mapPerson(link.user));
const mapGuests = (event) => event.guestLinks.map((link) => mapPerson(link.user));

const isoDate = (value) => {
  if (value === null || value === undefined) return null;
  const parsed = new Date(value);
  if (Number.isNaN(parsed.valueOf())) {
    throw createError(400, 'Invalid date format');
  }
  return parsed;
};

const validatePositiveInt = (value, message) => {
  if (value === null || value === undefined) return null;
  if (typeof value === 'number' && Number.isInteger(value) && value > 0) return value;
  if (typeof value === 'string') {
    const parsed = Number(value);
    if (Number.isInteger(parsed) && parsed > 0) return parsed;
  }
  throw createError(400, message);
};

const eventHasEnded = (event) => new Date(event.endTime) < new Date();

const eventHasStarted = (event) => new Date(event.startTime) <= new Date();

const isOrganizer = (event, userId) =>
  Array.isArray(event.organizers) &&
  event.organizers.some((link) => link.userId === userId);

const isGuest = (event, userId) =>
  Array.isArray(event.guests) &&
  event.guests.some((link) => link.userId === userId);



const presentCreatedEvent = (event) => ({
  id: event.id,
  name: event.name,
  description: event.description,
  location: event.location,
  startTime: event.startTime.toISOString(),
  endTime: event.endTime.toISOString(),
  capacity: event.capacity,
  pointsRemain: event.pointsRemain,
  pointsAwarded: event.pointsAwarded,
  published: event.published,
  organizers: [],
  guests: []
});

const presentEventSummary = (event) => ({
  id: event.id,
  name: event.name,
  location: event.location,
  startTime: event.startTime.toISOString(),
  endTime: event.endTime.toISOString(),
  capacity: event.capacity,
  pointsRemain: event.pointsRemain,
  pointsAwarded: event.pointsAwarded,
  published: event.published,
  numGuests: (event.guests || []).length
});

const presentEventDetail = (event, options) => {
  const common = {
    id: event.id,
    name: event.name,
    description: event.description,
    location: event.location,
    startTime: event.startTime.toISOString(),
    endTime: event.endTime.toISOString(),
    capacity: event.capacity,
    organizers: mapOrganizers(event)
  };

  if (options.showGuests) {
    return {
      ...common,
      guests: mapGuests(event),
      published: event.published,
      pointsRemain: event.pointsRemain,
      pointsAwarded: event.pointsAwarded
    };
  }

  return {
    ...common,
    numGuests: event.guestLinks.length
  };
};

const fetchEvent = async (eventId) => {
  const event = await prisma.event.findUnique({
    where: { id: eventId },
    include: {
      organizers: {
        include: {
          user: true
        }
      },
      guests: {
        include: {
          user: true
        }
      }
    }
  });

  if (!event) {
    throw createError(404, 'Event not found.');
  }

  return event;
};

const ensureManager = (user) => {
  if (!hasRole(user, 'manager', 'superuser')) {
    throw createError(403, 'Permission denied.');
  }
};

const validateEventTimes = (startTime, endTime) => {
  if (startTime && endTime && startTime >= endTime) {
    throw createError(400, 'Invalid event time.');
  }
};

const ensureCapacityAvailable = (event) => {
  if (event.capacity && event.guestLinks.length >= event.capacity) {
    throw createError(410, 'Event is at full capacity.');
  }
};

const incrementGuests = async (eventId, userId) => {
  await prisma.eventGuest.create({
    data: {
      eventId,
      userId
    }
  });
};

const decrementGuests = async (eventId, userId) => {
  await prisma.eventGuest.delete({
    where: {
      eventId_userId: {
        eventId,
        userId
      }
    }
  });
};

const createEvent = async ({ body, user }) => {
  ensureManager(user);

  const name = body.name;
  if (!name) {
    throw createError(400, 'Name is required.');
  }

  const description = body.description ?? '';
  const location = body.location;
  if (!location) {
    throw createError(400, 'Location is required.');
  }

  const startTime = isoDate(body.startTime);
  const endTime = isoDate(body.endTime);
  validateEventTimes(startTime, endTime);

  const capacity =
    body.capacity === null || body.capacity === undefined
      ? null
      : validatePositiveInt(body.capacity, 'Invalid event capacity.');

  const points = validatePositiveInt(body.points, 'Invalid event points.');

  const created = await prisma.event.create({
    data: {
      name,
      description,
      location,
      startTime,
      endTime,
      capacity,
      pointsTotal: points,
      pointsRemain: points,
      createdById: user.id
    }
  });

  return presentCreatedEvent({
    ...created,
    guestLinks: [],
    organizerLinks: []
  });
};

const listEvents = async ({ user, query }) => {
  const page = Number(query.page ?? 1);
  const limit = Number(query.limit ?? 10);

  if (!Number.isInteger(page) || page < 1) {
    throw createError(400, 'Invalid page number');
  }

  if (!Number.isInteger(limit) || limit < 1) {
    throw createError(400, 'Invalid limit number');
  }

  const startedFilter = query.started;
  const endedFilter = query.ended;

  if (startedFilter !== undefined && endedFilter !== undefined) {
    throw createError(400, 'Cannot filter by both started and ended.');
  }

  const where = {};

  if (query.name) {
    where.name = { contains: query.name };
  }

  if (query.location) {
    where.location = { contains: query.location };
  }

  if (startedFilter !== undefined) {
    const isStarted = startedFilter === 'true';
    where.startTime = isStarted ? { lte: new Date() } : { gt: new Date() };
  }

  if (endedFilter !== undefined) {
    const isEnded = endedFilter === 'true';
    where.endTime = isEnded ? { lte: new Date() } : { gt: new Date() };
  }

  if (hasRole(user, 'regular', 'cashier')) {
    where.published = true;
  } else if (query.published !== undefined) {
    where.published = query.published === 'true';
  }

  const baseEvents = await prisma.event.findMany({
    where,
    include: organizerInclude,
    orderBy: { id: 'asc' }
  });

  const showFull = query.showFull === 'true';

  const filtered = showFull
    ? baseEvents
    : baseEvents.filter((event) => {
        if (event.capacity == null) return true;
        const guestCount = (event.guests || []).length;
        return guestCount < event.capacity;
      });

  const count = filtered.length;
  const startIndex = (page - 1) * limit;
  const paged = filtered.slice(startIndex, startIndex + limit);

  return {
    count,
    results: paged.map((event) => presentEventSummary(event))
  };
};


const fetchEventForView = async ({ eventId, user }) => {
  const event = await fetchEvent(eventId);

  if (!event.published && hasRole(user, 'regular', 'cashier') && !isOrganizer(event, user.id)) {
    throw createError(404, 'Event not found.');
  }

  const privileged = hasRole(user, 'manager', 'superuser') || isOrganizer(event, user.id);

  return presentEventDetail(event, { showGuests: privileged });
};

const updateEvent = async ({ eventId, user, body }) => {
  const event = await fetchEvent(eventId);

  if (!hasRole(user, 'manager', 'superuser') && !isOrganizer(event, user.id)) {
    throw createError(403, 'Permission denied.');
  }

    const isManager = hasRole(user, 'manager', 'superuser');
    if (!isManager && body.points !== undefined && body.points !== null) {
      throw createError(403, 'Permission denied.');
    }

    if (!isManager && body.published !== undefined && body.published !== null) {
    throw createError(403, 'Permission denied.');
  }

  const data = {};
  if (body.name) data.name = body.name;
  if (body.description) data.description = body.description;
  if (body.location) data.location = body.location;

  if (body.startTime) {
    const nextStart = isoDate(body.startTime);
    if (eventHasStarted(event)) {
      throw createError(400, 'Invalid event time.');
    }
    validateEventTimes(nextStart, event.endTime);
    data.startTime = nextStart;
  }

  if (body.endTime) {
    const nextEnd = isoDate(body.endTime);
    validateEventTimes(event.startTime, nextEnd);
    data.endTime = nextEnd;
  }

  let newStart = event.startTime;
  let newEnd = event.endTime;

  if (body.startTime !== undefined && body.startTime !== null) {
    newStart = isoDate(body.startTime);
    data.startTime = newStart;
  }

  if (body.endTime !== undefined && body.endTime !== null) {
    newEnd = isoDate(body.endTime);
    data.endTime = newEnd;
  }

  if (body.startTime !== undefined || body.endTime !== undefined) {
    if (newStart < new Date()) {
      throw createError(400, 'Invalid event start time.');
    }
    if (newEnd <= newStart) {
      throw createError(400, 'Invalid event end time.');
    }
  }


  if (body.capacity !== null && body.capacity !== undefined) {
    const nextCapacity = validatePositiveInt(body.capacity, 'Invalid event capacity.');
    if (event.guestLinks.length > nextCapacity) {
      throw createError(400, 'Invalid event capacity.');
    }
    data.capacity = nextCapacity;
  }

  if (body.points !== null && body.points !== undefined) {
    const nextPoints = validatePositiveInt(body.points, 'Invalid event points.');
    if (nextPoints < event.pointsAwarded) {
      throw createError(400, 'Invalid event points.');
    }
    data.pointsTotal = nextPoints;
    data.pointsRemain = nextPoints - event.pointsAwarded;
  }

  if (body.published !== null && body.published !== undefined) {
    data.published = Boolean(body.published);
  }

  if (Object.keys(data).length === 0) {
    return {
      id: event.id,
      name: event.name,
      location: event.location
    };
  }

  const updated = await prisma.event.update({
    where: { id: event.id },
    data
  });

  const response = {
    id: updated.id,
    name: updated.name,
    location: updated.location
  };

  if ('published' in data) {
    response.published = updated.published;
  }
  if ('capacity' in data) {
    response.capacity = updated.capacity;
  }
  if ('pointsTotal' in data) {
    response.pointsRemain = updated.pointsRemain;
  }
  if ('startTime' in data) {
    response.startTime = updated.startTime.toISOString();
  }
  if ('endTime' in data) {
    response.endTime = updated.endTime.toISOString();
  }

  return response;
};

const deleteEvent = async ({ eventId, user }) => {
  ensureManager(user);
  const event = await prisma.event.findUnique({ where: { id: eventId } });
  if (!event) {
    throw createError(404, 'Event not found.');
  }
  if (event.published) {
    throw createError(400, 'Cannot delete published event.');
  }
  await prisma.event.delete({ where: { id: eventId } });
};

const addOrganizer = async ({ eventId, utorid, user }) => {
  ensureManager(user);
  const event = await fetchEvent(eventId);

  if (eventHasEnded(event)) {
    throw createError(410, 'Cannot add organizer after event end.');
  }

  if (!utorid) {
    throw createError(400, 'Utorid is required');
  }

  const person = await prisma.user.findUnique({ where: { utorid } });
  if (!person) {
    throw createError(404, 'User not found.');
  }

  if (isOrganizer(event, person.id)) {
    throw createError(400, 'User is already an organizer.');
  }

  if (isGuest(event, person.id)) {
    throw createError(400, 'Cannot add organizer as guest.');
  }

  await prisma.eventOrganizer.create({
    data: {
      eventId: event.id,
      userId: person.id
    }
  });

  const refreshed = await fetchEvent(eventId);
  return {
    id: refreshed.id,
    name: refreshed.name,
    location: refreshed.location,
    organizers: mapOrganizers(refreshed)
  };
};

const removeOrganizer = async ({ eventId, organizerUserId, user }) => {
  if (!hasRole(user, 'manager', 'superuser')) {
    throw createError(403, 'Permission denied.');
  }

  const event = await fetchEvent(eventId);

  if (eventHasEnded(event)) {
    throw createError(410, 'Cannot remove organizer after event end.');
  }

  const existing = (event.organizers || []).find(
    (o) => o.userId === organizerUserId
  );

  if (!existing) {
    throw createError(404, 'Organizer not found.');
  }

  await prisma.eventOrganizer.delete({
    where: {
      eventId_userId: {
        eventId,
        userId: organizerUserId
      }
    }
  });

  const refreshed = await fetchEvent(eventId);

  return {
    id: refreshed.id,
    name: refreshed.name,
    organizers: mapOrganizers(refreshed)
  };
};


const addGuest = async ({ eventId, utorid, user }) => {
  if (!hasRole(user, 'manager', 'superuser', 'cashier')) {
    throw createError(403, 'Permission denied.');
  }

  if (!utorid) {
    throw createError(400, 'Utorid is required');
  }

  const event = await fetchEvent(eventId);

  if (eventHasEnded(event)) {
    throw createError(410, 'Cannot add guest after event end.');
  }

  const person = await prisma.user.findUnique({ where: { utorid } });
  if (!person) {
    throw createError(404, 'User not found.');
  }

  if (isOrganizer(event, person.id)) {
    throw createError(400, 'Cannot add organizer as guest.');
  }

  if (isGuest(event, person.id)) {
    throw createError(400, 'User is already a guest.');
  }

  const currentGuests = (event.guests || []).length;
  if (event.capacity != null && currentGuests >= event.capacity) {
    throw createError(400, 'Event is full.');
  }

  await prisma.eventGuest.create({
    data: {
      eventId: event.id,
      userId: person.id
    }
  });

  const refreshed = await fetchEvent(eventId);
  const updatedGuests = refreshed.guests || [];
  const lastGuest = updatedGuests.find((g) => g.userId === person.id);

  return {
    id: refreshed.id,
    name: refreshed.name,
    location: refreshed.location,
    guestAdded: mapPerson(lastGuest ? lastGuest.user : person),
    numGuests: updatedGuests.length
  };
};

const addGuestSelf = async ({ eventId, user }) => {
  const event = await fetchEvent(eventId);

  const person = await prisma.user.findUnique({ where: { id: user.id } });
  if (!person) {
    throw createError(401, 'Unauthorized');
  }

  if (eventHasEnded(event)) {
    throw createError(410, 'Cannot add guest after event end.');
  }

  if (!event.published) {
    throw createError(404, 'Event not found.');
  }

  if (isGuest(event, person.id)) {
    throw createError(400, 'User is already a guest.');
  }

  ensureCapacityAvailable(event);

  await incrementGuests(event.id, person.id);
  const refreshed = await fetchEvent(event.id);

  return {
    id: refreshed.id,
    name: refreshed.name,
    location: refreshed.location,
    guestAdded: mapPerson(person),
    numGuests: refreshed.guestLinks.length
  };
};

const removeGuest = async ({ eventId, userId, user }) => {
  const event = await fetchEvent(eventId);

  const isPrivileged =
    hasRole(user, 'manager', 'superuser') || isOrganizer(event, user.id) || user.id === userId;

  if (!isPrivileged) {
    throw createError(403, 'Permission denied.');
  }

  if (eventHasEnded(event)) {
    throw createError(410, 'Cannot delete guest after event end.');
  }

  if (!isGuest(event, userId)) {
    throw createError(404, 'Guest not found.');
  }

  await decrementGuests(event.id, userId);
};

const removeGuestSelf = async ({ eventId, user }) => {
  const event = await fetchEvent(eventId);

  if (eventHasEnded(event)) {
    throw createError(410, 'Cannot delete guest after event end.');
  }

  if (!isGuest(event, user.id)) {
    throw createError(404, 'Guest not found.');
  }

  await decrementGuests(event.id, user.id);
};

const awardEventPoints = async ({ eventId, user, body }) => {
  const event = await fetchEvent(eventId);
  const requesterId = Number(user?.id);

  if (!Number.isFinite(requesterId)) {
    throw createError(401, 'Unauthorized');
  }

  const isManager = hasRole(user, 'manager', 'superuser');

  if (!isManager) {
    const organizerRecord = await prisma.eventOrganizer.findUnique({
      where: {
        eventId_userId: {
          eventId,
          userId: requesterId
        }
      },
      select: {
        eventId: true
      }
    });

    if (!organizerRecord) {
      throw createError(403, 'Permission denied.');
    }
  }

  if (body.type !== 'event') {
    throw createError(400, 'Unsupported transaction type');
  }

  const amount = Number(body.amount);
  if (!Number.isFinite(amount) || amount <= 0) {
    throw createError(400, 'Invalid points.');
  }

  const recipientUtorid = body.utorid;

  const recipients = [];

  if (recipientUtorid) {
    const guest = event.guestLinks.find((link) => link.user.utorid === recipientUtorid);
    if (!guest) {
      throw createError(400, 'User is not a guest.');
    }
    recipients.push(guest.user);
  } else {
    if (!event.guestLinks.length) {
      throw createError(400, 'User is not a guest.');
    }
    recipients.push(...event.guestLinks.map((link) => link.user));
  }

  const unitPoints = Math.round(amount);
  const requiredPoints = unitPoints * recipients.length;
  if (requiredPoints > event.pointsRemain) {
    throw createError(400, 'Invalid points.');
  }

  const creator = await prisma.user.findUnique({ where: { id: requesterId } });

  const results = await prisma.$transaction(async (tx) => {
    const payload = [];

    for (const recipient of recipients) {
      await tx.user.update({
        where: { id: recipient.id },
        data: {
          points: { increment: unitPoints }
        }
      });

      const transaction = await tx.transaction.create({
        data: {
          type: 'event',
          pointsDelta: unitPoints,
          remark: body.remark ?? null,
          userId: recipient.id,
          recipientId: recipient.id,
          createdById: requesterId,
          eventId,
          processed: true
        }
      });

      payload.push({
        id: transaction.id,
        recipient: recipient.utorid,
        awarded: unitPoints,
        type: 'event',
        relatedId: eventId,
        remark: body.remark ?? null,
        createdBy: creator?.utorid ?? null
      });
    }

    await tx.event.update({
      where: { id: eventId },
      data: {
        pointsRemain: { decrement: requiredPoints },
        pointsAwarded: { increment: requiredPoints }
      }
    });

    return payload;
  });

  return recipientUtorid ? results[0] : results;
};

module.exports = {
  createEvent,
  listEvents,
  fetchEventForView,
  updateEvent,
  deleteEvent,
  addOrganizer,
  removeOrganizer,
  addGuest,
  addGuestSelf,
  removeGuest,
  removeGuestSelf,
  awardEventPoints,
  createError
};
