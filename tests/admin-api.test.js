const request = require("supertest");
const http = require("http");

let app;
let server;

beforeAll(() => {
  // Require server.js after setting up to reuse same app instance
  app = require("../server");
  server = http.createServer(app);
});

afterAll((done) => {
  if (server) {
    server.close(done);
  } else {
    done();
  }
});

describe("Admin API auth", () => {
  test("rejects login without body", async () => {
    const res = await request(server).post("/admin/auth/login").send({});
    expect(res.status).toBe(400);
  });
});

