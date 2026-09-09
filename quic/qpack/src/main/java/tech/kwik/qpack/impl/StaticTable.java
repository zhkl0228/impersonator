/*
 * Copyright © 2019, 2020, 2021, 2022, 2023, 2024, 2025, 2026 Peter Doornbosch
 *
 * This file is part of Flupke, a HTTP3 Java library.
 *
 * Flupke is free software: you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation, either version 3 of the License, or (at your option)
 * any later version.
 *
 * Flupke is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License for
 * more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */
package tech.kwik.qpack.impl;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * https://www.rfc-editor.org/rfc/rfc9204.html#section-3.1
 * "The static table consists of a predefined list of field lines, each of which has a fixed index over time. (...)
 *  All entries in the static table have a name and a value. However, values can be empty (that is, have a length of 0).
 *  Each entry is identified by a unique index. Note that the QPACK static table is indexed from 0 (...)"
 */
public class StaticTable {

    public static final int MAX_TABLE_SIZE = 99;

    private static Pattern empty =        Pattern.compile("\\|\\s+\\|\\s+\\|\\s+\\|");
    private static Pattern nameOnly =     Pattern.compile("\\|\\s*(\\d+)\\s*" + "\\|\\s*([^\\|]+)\\s*" + "\\|\\s+\\|");
    private static Pattern nameValue =    Pattern.compile("\\|\\s*(\\d+)\\s*" + "\\|\\s*([^\\|]+)\\s*" + "\\|\\s*([^\\|]+)\\s*\\|");
    private static Pattern continuation = Pattern.compile("\\|\\s+"           + "\\|\\s*([^\\|]*)\\s*" + "\\|\\s*([^\\|]*)\\s*\\|");

    private final Map<TableEntry, TableEntry> entriesByName = new HashMap<>();
    private final TableEntry[] entriesByIndex = new TableEntry[MAX_TABLE_SIZE];

    public static StaticTable getInstance() {
        return Holder.INSTANCE;
    }

    private static class Holder {
        private static final StaticTable INSTANCE = new StaticTable();
    }

    private StaticTable() {
        loadTable();
    }

    private void loadTable() {
        String[] names = new String[MAX_TABLE_SIZE];
        String[] values = new String[MAX_TABLE_SIZE];

        try {
            InputStream resourceAsStream = this.getClass().getResourceAsStream("statictable.txt");
            BufferedReader reader = new BufferedReader(new InputStreamReader(resourceAsStream));

            String line;
            int lastIndex = 0;
            line = reader.readLine();
            while (line != null) {
                line = line.trim();
                if (empty.matcher(line).matches()) {
                    // Skip
                }
                else if (nameOnly.matcher(line).matches()) {
                    Matcher m = nameOnly.matcher(line);
                    m.matches();
                    names[Integer.parseInt(m.group(1).trim())] = m.group(2).trim();
                    values[Integer.parseInt(m.group(1).trim())] = "";
                    lastIndex = Integer.parseInt(m.group(1).trim());
                }
                else if (nameValue.matcher(line).matches()) {
                    Matcher m = nameValue.matcher(line);
                    m.matches();
                    names[Integer.parseInt(m.group(1).trim())] = m.group(2).trim();
                    values[Integer.parseInt(m.group(1).trim())] = m.group(3).trim();
                    lastIndex = Integer.parseInt(m.group(1).trim());
                }
                else if (continuation.matcher(line).matches()) {
                    Matcher m = continuation.matcher(line);
                    m.matches();
                    String namePart = m.group(1).trim();
                    String valuePart = m.group(2).trim();
                    if (!namePart.isBlank()) {
                        names[lastIndex] = names[lastIndex] + namePart;
                    }
                    if (!valuePart.isBlank()) {
                        values[lastIndex] = values[lastIndex] + valuePart;
                    }
                }
                else {
                    throw new RuntimeException("Internal error: parsing static table definition failed.");
                }

                line = reader.readLine();
            }

            fillTable(names, values);
        }
        catch (IOException e) {
            // Impossible when library is build correctly.
            throw new RuntimeException("Corrupt library, missing internal resource.");
        }
    }

    private void fillTable(String[] names, String[] values) {
        for (int i = 0; i < MAX_TABLE_SIZE; i++) {
            if (names[i] != null) {
                assert values[i] != null;
                TableEntry entry = new TableEntry(names[i], values[i], i);
                entriesByName.put(entry, entry);
                entriesByIndex[i] = entry;
            }
        }

        for (int i = 0; i < MAX_TABLE_SIZE; i++) {
            if (!entriesByName.containsKey(new TableEntry(names[i]))) {
                TableEntry nameOnlyEntry = new TableEntry(names[i], i);
                entriesByName.put(nameOnlyEntry, nameOnlyEntry);
            }
        }
    }

    public String lookupName(int index) {
        if (index < 0 || index >= MAX_TABLE_SIZE) {
            throw new HttpQPackDecompressionFailedException();
        }
        TableEntry result = entriesByIndex[index];
        if (result == null) {
            throw new HttpQPackDecompressionFailedException();
        }
        return result.getKey();
    }

    public TableEntry findByNameAndValue(String name, String value) {
        Objects.requireNonNull(name);
        Objects.requireNonNull(value);
        TableEntry nameAndValueEntry = entriesByName.get(new TableEntry(name, value));
        if (nameAndValueEntry != null) {
            return nameAndValueEntry;
        }
        else {
            TableEntry nameOnlyEntry = entriesByName.get(new TableEntry(name));
            return nameOnlyEntry;
        }
    }

    public Map.Entry<String, String> lookupNameValue(int index) {
        if (index < 0 || index >= MAX_TABLE_SIZE) {
            throw new HttpQPackDecompressionFailedException();
        }
        if (entriesByIndex[index] != null) {
            return entriesByIndex[index];
        }
        else {
            throw new HttpQPackDecompressionFailedException();
        }
    }
}
