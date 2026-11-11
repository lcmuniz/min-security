package io.github.lcmuniz.minsecurity;

import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;

import com.jayway.jsonpath.JsonPath;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;

@SpringBootTest(properties = {
        "app.jwt.secret=" + ApiIntegrationTests.SECRET,
        "app.demo.admin-password=admin-pass",
        "app.demo.user-password=user-pass"})
@AutoConfigureMockMvc
class ApiIntegrationTests {

    static final String SECRET = "dGVzdC1zZWNyZXQtdGhhdC1pcy1hdC1sZWFzdC0zMi1ieXRlcy1sb25n";

    @Autowired
    MockMvc mvc;

    @Autowired
    JwtProperties props;

    // --- public endpoint ---------------------------------------------------------------------------

    @Test
    void publicEndpointNeedsNoToken() throws Exception {
        mvc.perform(get("/api/public")).andExpect(status().isOk());
    }

    @Test
    void publicEndpointIgnoresAGarbageToken() throws Exception {
        mvc.perform(get("/api/public").header("Authorization", "Bearer not-a-jwt")).andExpect(status().isOk());
    }

    // --- login -------------------------------------------------------------------------------------

    @Test
    void loginReturnsATokenPairThatGrantsAccess() throws Exception {
        Tokens t = login("admin", "admin-pass");
        mvc.perform(get("/api/private").header("Authorization", "Bearer " + t.access()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.username").value("admin"))
                .andExpect(jsonPath("$.roles", containsInAnyOrder("ROLE_ADMIN", "ROLE_USER")));
    }

    @Test
    void wrongPasswordIs401() throws Exception {
        loginRaw("{\"username\":\"admin\",\"password\":\"nope\"}")
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.detail").value("Invalid credentials"));
    }

    @Test
    void unknownUserIs401() throws Exception {
        loginRaw("{\"username\":\"ghost\",\"password\":\"x\"}").andExpect(status().isUnauthorized());
    }

    @Test
    void missingFieldsAre400() throws Exception {
        loginRaw("{\"username\":\"admin\"}").andExpect(status().isBadRequest());
    }

    @Test
    void malformedJsonIs400() throws Exception {
        loginRaw("{not json").andExpect(status().isBadRequest());
    }

    // --- protected endpoints -----------------------------------------------------------------------

    @Test
    void privateEndpointWithoutTokenIs401() throws Exception {
        mvc.perform(get("/api/private")).andExpect(status().isUnauthorized());
    }

    @Test
    void privateEndpointWithGarbageTokenIs401() throws Exception {
        mvc.perform(get("/api/private").header("Authorization", "Bearer abc.def.ghi"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void refreshTokenCannotBeUsedAsAccessToken() throws Exception {
        Tokens t = login("admin", "admin-pass");
        mvc.perform(get("/api/private").header("Authorization", "Bearer " + t.refresh()))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void expiredAccessTokenIs401() throws Exception {
        Clock past = Clock.fixed(Instant.now().minus(Duration.ofHours(2)), ZoneOffset.UTC);
        String expired = new JwtService(props, past).accessToken("admin", List.of("ADMIN"));
        mvc.perform(get("/api/private").header("Authorization", "Bearer " + expired))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void tokenSignedWithAnotherKeyIs401() throws Exception {
        JwtProperties other = new JwtProperties(
                "b3RoZXItc2VjcmV0LW90aGVyLXNlY3JldC1vdGhlci1zZWNyZXQtMzI=", props.issuer(), null, null);
        String forged = new JwtService(other, Clock.systemUTC()).accessToken("admin", List.of("ADMIN"));
        mvc.perform(get("/api/private").header("Authorization", "Bearer " + forged))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void adminEndpointRequiresAdminRole() throws Exception {
        Tokens user = login("user", "user-pass");
        mvc.perform(get("/api/admin").header("Authorization", "Bearer " + user.access()))
                .andExpect(status().isForbidden());

        Tokens admin = login("admin", "admin-pass");
        mvc.perform(get("/api/admin").header("Authorization", "Bearer " + admin.access()))
                .andExpect(status().isOk());
    }

    // --- refresh -----------------------------------------------------------------------------------

    @Test
    void refreshKeepsTheUsersOwnRoles() throws Exception {
        Tokens t = refresh(login("user", "user-pass").refresh());
        mvc.perform(get("/api/private").header("Authorization", "Bearer " + t.access()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.roles", containsInAnyOrder("ROLE_USER")));
    }

    @Test
    void refreshTokenIsSingleUse() throws Exception {
        String original = login("admin", "admin-pass").refresh();
        refresh(original);
        refreshRaw(original).andExpect(status().isUnauthorized());
    }

    @Test
    void accessTokenCannotBeUsedToRefresh() throws Exception {
        refreshRaw(login("admin", "admin-pass").access()).andExpect(status().isUnauthorized());
    }

    @Test
    void garbageRefreshTokenIs401() throws Exception {
        refreshRaw("garbage").andExpect(status().isUnauthorized());
    }

    // --- logout ------------------------------------------------------------------------------------

    @Test
    void logoutRevokesTheRefreshToken() throws Exception {
        Tokens t = login("admin", "admin-pass");
        mvc.perform(post("/api/logout")
                        .header("Authorization", "Bearer " + t.access())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"refreshToken\":\"" + t.refresh() + "\"}"))
                .andExpect(status().isNoContent());
        refreshRaw(t.refresh()).andExpect(status().isUnauthorized());
    }

    @Test
    void logoutRequiresAuthentication() throws Exception {
        Tokens t = login("admin", "admin-pass");
        mvc.perform(post("/api/logout")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"refreshToken\":\"" + t.refresh() + "\"}"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void cannotLogOutSomeoneElsesRefreshToken() throws Exception {
        Tokens admin = login("admin", "admin-pass");
        Tokens user = login("user", "user-pass");
        mvc.perform(post("/api/logout")
                        .header("Authorization", "Bearer " + user.access())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"refreshToken\":\"" + admin.refresh() + "\"}"))
                .andExpect(status().isUnauthorized());
        refresh(admin.refresh());
    }

    // --- helpers -----------------------------------------------------------------------------------

    record Tokens(String access, String refresh) {
    }

    private ResultActions loginRaw(String json) throws Exception {
        return mvc.perform(post("/api/login").contentType(MediaType.APPLICATION_JSON).content(json));
    }

    private ResultActions refreshRaw(String token) throws Exception {
        return mvc.perform(post("/api/refresh").contentType(MediaType.APPLICATION_JSON)
                .content("{\"refreshToken\":\"" + token + "\"}"));
    }

    private Tokens login(String username, String password) throws Exception {
        String body = loginRaw("{\"username\":\"" + username + "\",\"password\":\"" + password + "\"}")
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();
        return new Tokens(JsonPath.read(body, "$.accessToken"), JsonPath.read(body, "$.refreshToken"));
    }

    private Tokens refresh(String refreshToken) throws Exception {
        String body = refreshRaw(refreshToken).andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();
        return new Tokens(JsonPath.read(body, "$.accessToken"), JsonPath.read(body, "$.refreshToken"));
    }
}
