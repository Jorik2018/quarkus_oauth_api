package org.isobit.app.controller;

import javax.sql.DataSource;
import java.sql.Connection;
import java.sql.DatabaseMetaData;
import java.sql.ResultSet;
import java.util.ArrayList;
import java.util.List;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

import io.quarkus.security.Authenticated;
import jakarta.inject.Inject;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.PathParam;

@Path("/database")
@Authenticated
@Produces(MediaType.APPLICATION_JSON)
public class DatabaseController {

    @Inject
    DataSource dataSource;

    @GET
    @Path("/tables")
    public Response getTables() {

        List<TableInfo> tables = new ArrayList<>();

        try (Connection connection = dataSource.getConnection()) {

            DatabaseMetaData metadata = connection.getMetaData();

            try (ResultSet rs = metadata.getTables(
                    connection.getCatalog(),
                    null,
                    "%",
                    new String[] { "TABLE" })) {

                while (rs.next()) {
                    tables.add(new TableInfo(
                            rs.getString("TABLE_NAME"),
                            rs.getString("TABLE_CAT"),
                            rs.getString("TABLE_SCHEM"),
                            rs.getString("TABLE_TYPE")));
                }
            }

            return Response.ok(tables).build();

        } catch (Exception e) {
            return Response
                    .serverError()
                    .entity(
                            new ErrorResponse(e.getMessage()))
                    .build();
        }
    }

    public record ErrorResponse(String msg) {
    }

    @GET
    @Path("/table/{name}")
    public Response getTableDetail(
            @jakarta.ws.rs.PathParam("name") String tableName) {

        try (Connection connection = dataSource.getConnection()) {

            DatabaseMetaData metadata = connection.getMetaData();
            String catalog = connection.getCatalog();

            List<Map<String, Object>> columns = new ArrayList<>();
            Set<String> primaryKeys = new HashSet<>();

            // Primary Keys
            try (ResultSet rs = metadata.getPrimaryKeys(
                    catalog,
                    null,
                    tableName)) {
                while (rs.next()) {
                    primaryKeys.add(
                            rs.getString("COLUMN_NAME"));
                }
            }

            // Columnas
            try (ResultSet rs = metadata.getColumns(
                    catalog,
                    null,
                    tableName,
                    "%")) {

                while (rs.next()) {

                    String columnName = rs.getString("COLUMN_NAME");

                    Map<String, Object> column = new LinkedHashMap<>();

                    column.put("name", columnName);
                    column.put(
                            "type",
                            rs.getString("TYPE_NAME"));
                    column.put(
                            "size",
                            rs.getInt("COLUMN_SIZE"));
                    column.put(
                            "decimalDigits",
                            rs.getInt("DECIMAL_DIGITS"));
                    column.put(
                            "nullable",
                            rs.getInt("NULLABLE") == DatabaseMetaData.columnNullable);
                    column.put(
                            "defaultValue",
                            rs.getString("COLUMN_DEF"));
                    column.put(
                            "autoIncrement",
                            "YES".equalsIgnoreCase(
                                    rs.getString("IS_AUTOINCREMENT")));
                    column.put(
                            "primaryKey",
                            primaryKeys.contains(columnName));

                    columns.add(column);
                }
            }

            if (columns.isEmpty()) {
                return Response
                        .status(Response.Status.NOT_FOUND)
                        .entity(Map.of(
                                "msg",
                                "Tabla no encontrada: " + tableName))
                        .build();
            }

            Map<String, Object> result = new LinkedHashMap<>();

            result.put("name", tableName);
            result.put("catalog", catalog);
            result.put("columns", columns);

            return Response.ok(result).build();

        } catch (Exception e) {
            return Response
                    .serverError()
                    .entity(Map.of(
                            "msg",
                            "Error obteniendo tabla: "
                                    + e.getMessage()))
                    .build();
        }
    }

}