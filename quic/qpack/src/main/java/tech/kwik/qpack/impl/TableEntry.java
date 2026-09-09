/*
 * Copyright © 2026 Peter Doornbosch
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

import java.util.Map;

public class TableEntry implements Map.Entry<String, String> {

    private final String name;
    private final String value;
    private final int index;

    public TableEntry(String name, String value, int index) {
        this.name = name;
        this.value = value;
        this.index = index;
    }

    public TableEntry(String name, String value) {
        this.name = name;
        this.value = value;
        this.index = -1;
    }

    public TableEntry(String name, int index) {
        this.name = name;
        this.value = "";
        this.index = index;
    }

    public TableEntry(String name) {
        this.name = name;
        this.value = "";
        this.index = -1;
    }

    @Override
    public String getKey() {
        return name;
    }

    @Override
    public String getValue() {
        return value;
    }

    @Override
    public String setValue(String value) {
        throw new UnsupportedOperationException();
    }

    public int getIndex() {
        return index;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        TableEntry that = (TableEntry) o;
        return java.util.Objects.equals(name, that.name) &&
               java.util.Objects.equals(value, that.value);
    }

    @Override
    public int hashCode() {
        return java.util.Objects.hash(name, value);
    }

    public boolean isValueEmpty() {
        return value.isEmpty();
    }
}
